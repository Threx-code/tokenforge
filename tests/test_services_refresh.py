"""
Tests for tokenforge.services.refresh — create, rotate, revoke, cleanup.
"""

import uuid

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from tokenforge.models import RefreshToken
from tokenforge.services.refresh import (
    cleanup_expired_tokens,
    create_refresh_token,
    revoke_all_for_user,
    revoke_by_family,
    rotate_refresh_token,
)

User = get_user_model()
pytestmark = pytest.mark.django_db


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def user(db):
    return User.objects.create_user(username="svc_user", password="pass")


@pytest.fixture()
def user2(db):
    return User.objects.create_user(username="svc_user2", password="pass")


@pytest.fixture()
def raw_token_and_instance(user):
    """Return (raw_token, RefreshToken) for a fresh token."""
    return create_refresh_token(user=user, fingerprint="fp-test")


# ── create_refresh_token ──────────────────────────────────────────────────────


class TestCreateRefreshToken:
    def test_returns_tuple_of_str_and_instance(self, user):
        raw, instance = create_refresh_token(user=user)
        assert isinstance(raw, str)
        assert isinstance(instance, RefreshToken)

    def test_raw_token_is_non_empty(self, user):
        raw, _ = create_refresh_token(user=user)
        assert len(raw) > 0

    def test_token_hash_stored_not_raw(self, user):
        raw, instance = create_refresh_token(user=user)
        # The stored hash must NOT equal the raw token
        assert instance.token_hash != raw
        # The hash must be a 64-char hex string (SHA-256)
        assert len(instance.token_hash) == 64
        int(instance.token_hash, 16)  # must be valid hex

    def test_user_assigned(self, user):
        _, instance = create_refresh_token(user=user)
        assert instance.user_id == user.id

    def test_fingerprint_stored(self, user):
        _, instance = create_refresh_token(user=user, fingerprint="fp-stored")
        assert instance.fingerprint == "fp-stored"

    def test_empty_fingerprint_allowed(self, user):
        _, instance = create_refresh_token(user=user)
        assert instance.fingerprint == ""

    def test_custom_token_family_used(self, user):
        family = uuid.uuid4()
        _, instance = create_refresh_token(user=user, token_family=family)
        assert instance.token_family == family

    def test_new_family_generated_when_none(self, user):
        _, inst1 = create_refresh_token(user=user)
        _, inst2 = create_refresh_token(user=user)
        assert inst1.token_family != inst2.token_family

    def test_expires_at_is_in_future(self, user):
        _, instance = create_refresh_token(user=user)
        assert instance.expires_at > timezone.now()

    def test_not_revoked_on_creation(self, user):
        _, instance = create_refresh_token(user=user)
        assert instance.revoked is False

    def test_each_call_returns_different_raw_token(self, user):
        raw1, _ = create_refresh_token(user=user)
        raw2, _ = create_refresh_token(user=user)
        assert raw1 != raw2


# ── rotate_refresh_token — happy path ────────────────────────────────────────


class TestRotateRefreshTokenHappyPath:
    def test_returns_new_raw_token_and_instance(self, raw_token_and_instance):
        raw, _ = raw_token_and_instance
        new_raw, new_instance = rotate_refresh_token(raw_token=raw)
        assert isinstance(new_raw, str)
        assert isinstance(new_instance, RefreshToken)

    def test_new_raw_token_differs_from_old(self, raw_token_and_instance):
        raw, _ = raw_token_and_instance
        new_raw, _ = rotate_refresh_token(raw_token=raw)
        assert new_raw != raw

    def test_old_token_is_revoked(self, raw_token_and_instance):
        raw, old_instance = raw_token_and_instance
        rotate_refresh_token(raw_token=raw)
        old_instance.refresh_from_db()
        assert old_instance.revoked is True

    def test_old_token_has_revoked_at_set(self, raw_token_and_instance):
        raw, old_instance = raw_token_and_instance
        rotate_refresh_token(raw_token=raw)
        old_instance.refresh_from_db()
        assert old_instance.revoked_at is not None

    def test_old_token_replaced_by_new(self, raw_token_and_instance):
        raw, old_instance = raw_token_and_instance
        _, new_instance = rotate_refresh_token(raw_token=raw)
        old_instance.refresh_from_db()
        assert old_instance.replaced_by_id == new_instance.id

    def test_new_token_belongs_to_same_family(self, raw_token_and_instance):
        raw, old_instance = raw_token_and_instance
        _, new_instance = rotate_refresh_token(raw_token=raw)
        assert new_instance.token_family == old_instance.token_family

    def test_new_token_is_not_revoked(self, raw_token_and_instance):
        raw, _ = raw_token_and_instance
        _, new_instance = rotate_refresh_token(raw_token=raw)
        assert new_instance.revoked is False

    def test_fingerprint_carried_over_when_not_provided(self, user):
        raw, _ = create_refresh_token(user=user, fingerprint="original-fp")
        _, new_instance = rotate_refresh_token(raw_token=raw)
        assert new_instance.fingerprint == "original-fp"

    def test_new_fingerprint_used_when_provided(self, user):
        raw, _ = create_refresh_token(user=user, fingerprint="old-fp")
        _, new_instance = rotate_refresh_token(raw_token=raw, fingerprint="new-fp")
        assert new_instance.fingerprint == "new-fp"


# ── rotate_refresh_token — error cases ───────────────────────────────────────


class TestRotateRefreshTokenErrors:
    def test_invalid_token_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid refresh token"):
            rotate_refresh_token(raw_token="this-token-does-not-exist")

    def test_expired_token_raises_value_error(self, user):
        """Rotating an expired token must raise ValueError."""
        raw, instance = create_refresh_token(user=user)
        instance.expires_at = timezone.now() - timezone.timedelta(seconds=1)
        instance.save(update_fields=["expires_at"])
        with pytest.raises(ValueError, match="Refresh token expired"):
            rotate_refresh_token(raw_token=raw)

    def test_already_used_token_raises_replay_error(self, raw_token_and_instance):
        raw, _ = raw_token_and_instance
        # First rotation succeeds
        rotate_refresh_token(raw_token=raw)
        # Second use of the same (now-revoked) token triggers replay
        with pytest.raises(ValueError, match="Token replay detected"):
            rotate_refresh_token(raw_token=raw)


# ── Replay detection — revoke entire family ───────────────────────────────────


class TestReplayDetection:
    def test_replay_raises_value_error(self, user):
        """Replaying a revoked token must raise ValueError('Token replay detected')."""
        raw1, _ = create_refresh_token(user=user, fingerprint="fp")
        rotate_refresh_token(raw_token=raw1)  # first use — revokes raw1

        # Replay the already-revoked raw1
        with pytest.raises(ValueError, match="Token replay detected"):
            rotate_refresh_token(raw_token=raw1)

    def test_replay_does_not_affect_other_families(self, user):
        """Replay detection must not revoke tokens from different families."""
        raw_a, inst_a = create_refresh_token(user=user, fingerprint="fp-a")
        raw_b, inst_b = create_refresh_token(user=user, fingerprint="fp-b")

        # Rotate A once, then replay A's original token
        rotate_refresh_token(raw_token=raw_a)
        with pytest.raises(ValueError, match="Token replay detected"):
            rotate_refresh_token(raw_token=raw_a)

        # Family B should still be intact
        inst_b.refresh_from_db()
        assert inst_b.revoked is False

    def test_revoke_by_family_revokes_all_in_family(self, user):
        """revoke_by_family() (called by replay detection) must revoke all family tokens."""
        import uuid as _uuid

        family = _uuid.uuid4()
        _, t1 = create_refresh_token(user=user, token_family=family)
        _, t2 = create_refresh_token(user=user, token_family=family)

        revoke_by_family(family, reason="replay_detection")

        t1.refresh_from_db()
        t2.refresh_from_db()
        assert t1.revoked is True
        assert t2.revoked is True


# ── revoke_by_family ─────────────────────────────────────────────────────────


class TestRevokeByFamily:
    def test_revokes_all_tokens_in_family(self, user):
        family = uuid.uuid4()
        _, t1 = create_refresh_token(user=user, token_family=family)
        _, t2 = create_refresh_token(user=user, token_family=family)
        count = revoke_by_family(family)
        assert count == 2
        t1.refresh_from_db()
        t2.refresh_from_db()
        assert t1.revoked is True
        assert t2.revoked is True

    def test_does_not_revoke_already_revoked(self, user):
        family = uuid.uuid4()
        _, t1 = create_refresh_token(user=user, token_family=family)
        t1.revoked = True
        t1.revoked_at = timezone.now()
        t1.save(update_fields=["revoked", "revoked_at"])
        _, t2 = create_refresh_token(user=user, token_family=family)
        count = revoke_by_family(family)
        assert count == 1  # Only t2 was active

    def test_returns_zero_for_unknown_family(self):
        count = revoke_by_family(uuid.uuid4())
        assert count == 0

    def test_does_not_affect_different_family(self, user):
        family_a = uuid.uuid4()
        family_b = uuid.uuid4()
        _, t_b = create_refresh_token(user=user, token_family=family_b)
        revoke_by_family(family_a)
        t_b.refresh_from_db()
        assert t_b.revoked is False


# ── revoke_all_for_user ───────────────────────────────────────────────────────


class TestRevokeAllForUser:
    def test_revokes_all_tokens_for_user(self, user):
        _, t1 = create_refresh_token(user=user)
        _, t2 = create_refresh_token(user=user)
        count = revoke_all_for_user(user)
        assert count == 2
        t1.refresh_from_db()
        t2.refresh_from_db()
        assert t1.revoked is True
        assert t2.revoked is True

    def test_does_not_affect_other_users(self, user, user2):
        _, t_other = create_refresh_token(user=user2)
        _, t_mine = create_refresh_token(user=user)
        revoke_all_for_user(user)
        t_other.refresh_from_db()
        assert t_other.revoked is False

    def test_returns_zero_when_no_tokens(self, user):
        count = revoke_all_for_user(user)
        assert count == 0

    def test_skips_already_revoked_tokens(self, user):
        _, t = create_refresh_token(user=user)
        t.revoked = True
        t.revoked_at = timezone.now()
        t.save(update_fields=["revoked", "revoked_at"])
        count = revoke_all_for_user(user)
        assert count == 0


# ── cleanup_expired_tokens ───────────────────────────────────────────────────


class TestCleanupExpiredTokens:
    def test_deletes_old_revoked_tokens(self, user):
        _, t = create_refresh_token(user=user)
        # Manually mark revoked and set revoked_at in the past
        cutoff = timezone.now() - timezone.timedelta(days=91)
        t.revoked = True
        t.revoked_at = cutoff
        t.save(update_fields=["revoked", "revoked_at"])
        count = cleanup_expired_tokens(older_than_days=90)
        assert count == 1
        assert not RefreshToken.objects.filter(pk=t.pk).exists()

    def test_preserves_recently_revoked_tokens(self, user):
        _, t = create_refresh_token(user=user)
        t.revoked = True
        t.revoked_at = timezone.now() - timezone.timedelta(days=1)
        t.save(update_fields=["revoked", "revoked_at"])
        count = cleanup_expired_tokens(older_than_days=90)
        assert count == 0
        assert RefreshToken.objects.filter(pk=t.pk).exists()

    def test_preserves_active_tokens(self, user):
        _, t = create_refresh_token(user=user)
        # Active (not revoked) tokens must never be deleted
        count = cleanup_expired_tokens(older_than_days=0)
        assert count == 0
        assert RefreshToken.objects.filter(pk=t.pk).exists()

    def test_returns_correct_count(self, user):
        old = timezone.now() - timezone.timedelta(days=100)
        for _ in range(3):
            _, t = create_refresh_token(user=user)
            t.revoked = True
            t.revoked_at = old
            t.save(update_fields=["revoked", "revoked_at"])
        count = cleanup_expired_tokens(older_than_days=90)
        assert count == 3

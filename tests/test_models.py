"""
Tests for tokenforge.models — RefreshToken model fields, properties,
and get_token_model().
"""

import uuid

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from tokenforge.models import RefreshToken, get_token_model

User = get_user_model()
pytestmark = pytest.mark.django_db


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def user(db):
    return User.objects.create_user(username="testuser", password="pass")


@pytest.fixture()
def token(user):
    return RefreshToken.objects.create(
        user=user,
        token_hash="abc123hash",
        token_family=uuid.uuid4(),
        fingerprint="fp-xyz",
        expires_at=timezone.now() + timezone.timedelta(days=30),
    )


# ── get_token_model ───────────────────────────────────────────────────────────


class TestGetTokenModel:
    def test_returns_refresh_token_class(self):
        model = get_token_model()
        assert model is RefreshToken

    def test_raises_lookup_error_for_bad_model(self, settings):
        settings.TOKENFORGE = {
            "ACCESS_TOKEN_SIGNING_KEY": "test-signing-key-not-for-production-use",
            "TOKEN_MODEL": "nonexistent.BadModel",
            "REFRESH_TOKEN_COOKIE_SECURE": False,
        }
        from tokenforge.settings import reload_settings

        reload_settings()
        with pytest.raises(LookupError, match="TOKEN_MODEL"):
            get_token_model()
        # Restore
        settings.TOKENFORGE = {
            "ACCESS_TOKEN_SIGNING_KEY": "test-signing-key-not-for-production-use",
            "REFRESH_TOKEN_COOKIE_SECURE": False,
        }
        reload_settings()


# ── RefreshToken fields ───────────────────────────────────────────────────────


class TestRefreshTokenFields:
    def test_id_is_uuid(self, token):
        assert isinstance(token.id, uuid.UUID)

    def test_token_family_is_uuid(self, token):
        assert isinstance(token.token_family, uuid.UUID)

    def test_revoked_defaults_to_false(self, token):
        assert token.revoked is False

    def test_revoked_at_defaults_to_none(self, token):
        assert token.revoked_at is None

    def test_replaced_by_defaults_to_none(self, token):
        assert token.replaced_by is None

    def test_str_contains_user_and_status(self, token):
        s = str(token)
        assert "active" in s

    def test_str_shows_revoked_when_revoked(self, token):
        token.revoked = True
        assert "revoked" in str(token)


# ── is_expired property ───────────────────────────────────────────────────────


class TestIsExpired:
    def test_not_expired_when_future(self, token):
        assert token.is_expired is False

    def test_expired_when_past(self, user):
        expired = RefreshToken.objects.create(
            user=user,
            token_hash="expiredhash",
            token_family=uuid.uuid4(),
            expires_at=timezone.now() - timezone.timedelta(seconds=1),
        )
        assert expired.is_expired is True


# ── is_usable property ────────────────────────────────────────────────────────


class TestIsUsable:
    def test_active_and_not_expired_is_usable(self, token):
        assert token.is_usable is True

    def test_revoked_is_not_usable(self, token):
        token.revoked = True
        assert token.is_usable is False

    def test_expired_is_not_usable(self, user):
        expired = RefreshToken.objects.create(
            user=user,
            token_hash="exphash2",
            token_family=uuid.uuid4(),
            expires_at=timezone.now() - timezone.timedelta(seconds=1),
        )
        assert expired.is_usable is False


# ── Meta / DB ─────────────────────────────────────────────────────────────────


class TestRefreshTokenDb:
    def test_token_hash_unique(self, user):
        family = uuid.uuid4()
        RefreshToken.objects.create(
            user=user,
            token_hash="unique-hash-001",
            token_family=family,
            expires_at=timezone.now() + timezone.timedelta(days=1),
        )
        from django.db import IntegrityError

        with pytest.raises(IntegrityError):
            RefreshToken.objects.create(
                user=user,
                token_hash="unique-hash-001",
                token_family=family,
                expires_at=timezone.now() + timezone.timedelta(days=1),
            )

    def test_db_table_name(self):
        assert RefreshToken._meta.db_table == "tokenforge_refresh_tokens"

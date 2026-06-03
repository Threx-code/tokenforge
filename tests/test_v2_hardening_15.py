"""v1.5 tests — H4 (durable replay revocation), L2 (reuse grace), L5 (active
cap), M1 (device-gate fail-open warning), M4 (non-Postgres warning)."""

import warnings
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any
from unittest import mock

import pytest
from django.conf import settings as dj_settings
from django.contrib.auth import get_user_model
from django.test import override_settings

from tokenforge.apps import TokenForgeConfig
from tokenforge.models import RefreshToken
from tokenforge.services.refresh import RefreshTokenService
from tokenforge.settings import reload_settings

User = get_user_model()
pytestmark = pytest.mark.django_db


@contextmanager
def tf_settings(**overrides: Any):
    merged = {**getattr(dj_settings, "TOKENFORGE", {}), **overrides}
    cm = override_settings(TOKENFORGE=merged)
    cm.enable()
    reload_settings()
    try:
        yield
    finally:
        cm.disable()
        reload_settings()


@pytest.fixture()
def user(db: Any) -> Any:
    return User.objects.create_user(username="h15_user", password="pass")


# ── H4 — replay revocation is durable (not rolled back by the raise) ──────────


class TestReplayDurability:
    def test_replay_persists_family_revocation(self, user: Any) -> None:
        raw_a, _ = RefreshTokenService.create(user=user, fingerprint="fp")
        _raw_b, tok_b = RefreshTokenService.rotate(raw_token=raw_a, fingerprint="fp")  # a→b
        with pytest.raises(ValueError, match="replay"):
            RefreshTokenService.rotate(raw_token=raw_a, fingerprint="fp")  # replay a
        # The whole family — including the active child b — is now revoked.
        tok_b.refresh_from_db()
        assert tok_b.revoked is True


# ── L2 — refresh-reuse grace window ───────────────────────────────────────────


class TestReuseGrace:
    def test_grace_rotates_instead_of_replay(self, user: Any) -> None:
        raw_a, _ = RefreshTokenService.create(user=user, fingerprint="fp")
        raw_b, tok_b = RefreshTokenService.rotate(raw_token=raw_a, fingerprint="fp")
        with tf_settings(REFRESH_REUSE_GRACE_SECONDS=30):
            raw_c, _tok_c = RefreshTokenService.rotate(raw_token=raw_a, fingerprint="fp")  # reuse a
        # The reuse was treated as a rotation of the current token b → c.
        tok_b.refresh_from_db()
        assert tok_b.revoked is True  # b rotated to c
        assert raw_c != raw_b
        # The family was NOT nuked: c is active.
        assert RefreshToken.objects.filter(user=user, revoked=False).count() == 1

    def test_default_no_grace_is_replay(self, user: Any) -> None:
        raw_a, _ = RefreshTokenService.create(user=user, fingerprint="fp")
        _raw_b, tok_b = RefreshTokenService.rotate(raw_token=raw_a, fingerprint="fp")
        with pytest.raises(ValueError, match="replay"):
            RefreshTokenService.rotate(raw_token=raw_a, fingerprint="fp")
        tok_b.refresh_from_db()
        assert tok_b.revoked is True  # family nuked

    def test_grace_requires_fingerprint_match(self, user: Any) -> None:
        raw_a, _ = RefreshTokenService.create(user=user, fingerprint="fp-A")
        RefreshTokenService.rotate(raw_token=raw_a, fingerprint="fp-A")
        with tf_settings(REFRESH_REUSE_GRACE_SECONDS=30), pytest.raises(ValueError, match="replay"):
            RefreshTokenService.rotate(raw_token=raw_a, fingerprint="fp-DIFFERENT")


# ── L5 — active-token cap ─────────────────────────────────────────────────────


class TestActiveTokenCap:
    def test_cap_revokes_excess_logins(self, user: Any) -> None:
        with tf_settings(MAX_ACTIVE_REFRESH_TOKENS_PER_USER=2):
            RefreshTokenService.create(user=user)
            RefreshTokenService.create(user=user)
            RefreshTokenService.create(user=user)  # 3rd login → oldest pruned
        assert RefreshToken.objects.filter(user=user, revoked=False).count() == 2
        assert RefreshToken.objects.filter(user=user, revoked=True).count() == 1

    def test_rotation_does_not_trigger_cap(self, user: Any) -> None:
        with tf_settings(MAX_ACTIVE_REFRESH_TOKENS_PER_USER=2):
            raw1, _t1 = RefreshTokenService.create(user=user)
            _raw2, t2 = RefreshTokenService.create(user=user)
            RefreshTokenService.rotate(raw_token=raw1)  # rotation, not a new login
        t2.refresh_from_db()
        assert t2.revoked is False  # the other session is not pruned by a rotation


# ── M1 — built-in device gate fail-open warning ───────────────────────────────


class TestDeviceGateFailOpen:
    def test_warns_when_session_lacks_gate_fields(self) -> None:
        with pytest.warns(UserWarning, match="no-ops"):
            RefreshTokenService._default_device_gate(
                SimpleNamespace()
            )  # no fields → silent no-op → warn

    def test_no_warning_when_fields_present(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            RefreshTokenService._default_device_gate(
                SimpleNamespace(revoked=False, risk_score=0, bot_score=0)
            )

    def test_raises_on_revoked(self) -> None:
        with pytest.raises(ValueError, match="revoked"):
            RefreshTokenService._default_device_gate(SimpleNamespace(revoked=True))

    def test_raises_on_high_risk(self) -> None:
        with pytest.raises(ValueError, match="risk"):
            RefreshTokenService._default_device_gate(SimpleNamespace(risk_score=100))


# ── M4 — non-Postgres concurrency warning ─────────────────────────────────────


class TestConcurrencyDbWarning:
    def test_warns_on_non_postgres(self) -> None:
        with (
            mock.patch("django.db.connection", SimpleNamespace(vendor="sqlite")),
            tf_settings(REPLAY_DETECTION_ENABLED=True),
            pytest.warns(UserWarning, match="postgresql"),
        ):
            TokenForgeConfig._warn_concurrency_db()

    def test_no_warning_on_postgres(self) -> None:
        with (
            mock.patch("django.db.connection", SimpleNamespace(vendor="postgresql")),
            warnings.catch_warnings(),
        ):
            warnings.simplefilter("error")
            TokenForgeConfig._warn_concurrency_db()

"""2.0 flip tests — the deliberate breaking changes:
- secure cookie-name prefix (USE_SECURE_COOKIE_PREFIX, SD-1)
- fail-closed exchange creation at the view layer (SD-2)
- onetime accurate active-token tracking (drift fix)
"""

from contextlib import contextmanager
from typing import Any
from unittest import mock

import pytest
from django.conf import settings as dj_settings
from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework.test import APIClient

from tokenforge.security.cookies import RefreshCookie
from tokenforge.services.refresh import RefreshTokenService
from tokenforge.settings import reload_settings
from tokenforge.tokens import AccessToken, OneTimeStore

User = get_user_model()


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


# ── SD-1 — `__Secure-` cookie-name prefix ─────────────────────────────────────


class TestSecureCookiePrefix:
    def test_prefix_applied_when_secure(self) -> None:
        with tf_settings(USE_SECURE_COOKIE_PREFIX=True, REFRESH_TOKEN_COOKIE_SECURE=True):
            assert RefreshCookie.name() == "__Secure-refresh_token"

    def test_no_prefix_when_not_secure(self) -> None:
        # `__Secure-` is invalid on a non-Secure cookie — the browser would drop
        # it — so the prefix is skipped in local HTTP dev.
        with tf_settings(USE_SECURE_COOKIE_PREFIX=True, REFRESH_TOKEN_COOKIE_SECURE=False):
            assert RefreshCookie.name() == "refresh_token"

    def test_no_prefix_when_disabled(self) -> None:
        with tf_settings(USE_SECURE_COOKIE_PREFIX=False, REFRESH_TOKEN_COOKIE_SECURE=True):
            assert RefreshCookie.name() == "refresh_token"

    @pytest.mark.django_db
    def test_refresh_round_trips_with_prefixed_cookie(self) -> None:
        user = User.objects.create_user(username="prefix_user", password="pass")
        raw, _ = RefreshTokenService.create(user=user, fingerprint="")
        with tf_settings(USE_SECURE_COOKIE_PREFIX=True, REFRESH_TOKEN_COOKIE_SECURE=True):
            client = APIClient()
            client.cookies["__Secure-refresh_token"] = raw
            resp = client.post(
                "/api/v1/auth/token/refresh/", HTTP_X_REQUESTED_WITH="XMLHttpRequest"
            )
            assert resp.status_code == 200
            # The rotated cookie comes back under the prefixed name.
            assert "__Secure-refresh_token" in resp.cookies
            assert "refresh_token" not in resp.cookies


# ── SD-2 — exchange create is fail-closed at the view ─────────────────────────


class TestExchangeCreateFailClosed:
    url = "/api/v1/auth/exchange/create/"

    @pytest.mark.django_db
    def test_unset_allowlist_returns_403(self) -> None:
        user = User.objects.create_user(username="fc_user", password="pass")
        access, _ = AccessToken.create(user_id=str(user.id), device_session_id="s", fingerprint="")
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        with tf_settings(EXCHANGE_ALLOWED_ORIGINS=None):
            resp = client.post(
                self.url, {"target_origin": "https://app.example.com"}, format="json"
            )
        assert resp.status_code == 403

    @pytest.mark.django_db
    def test_disallowed_origin_returns_403(self) -> None:
        user = User.objects.create_user(username="fc_user2", password="pass")
        access, _ = AccessToken.create(user_id=str(user.id), device_session_id="s", fingerprint="")
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        with tf_settings(EXCHANGE_ALLOWED_ORIGINS=["https://app.example.com"]):
            resp = client.post(
                self.url, {"target_origin": "https://evil.example.com"}, format="json"
            )
        assert resp.status_code == 403


# ── onetime — accurate, self-pruning active-token tracking ────────────────────


class TestOnetimeActiveTracking:
    def setup_method(self) -> None:
        from django.core.cache import cache

        cache.clear()

    store = OneTimeStore("ns")

    def test_track_and_count(self) -> None:
        self.store.track("owner-1", "tok-a", ttl=60)
        self.store.track("owner-1", "tok-b", ttl=60)
        assert self.store.count_active("owner-1") == 2

    def test_untrack_decrements(self) -> None:
        self.store.track("owner-2", "tok-a", ttl=60)
        self.store.track("owner-2", "tok-b", ttl=60)
        self.store.untrack("owner-2", "tok-a")
        assert self.store.count_active("owner-2") == 1

    def test_untrack_last_clears_key(self) -> None:
        from django.core.cache import cache

        self.store.track("owner-3", "tok-a", ttl=60)
        self.store.untrack("owner-3", "tok-a")
        assert cache.get("tokenforge:ns_active:owner-3") is None

    def test_owners_are_isolated(self) -> None:
        self.store.track("owner-A", "tok", ttl=60)
        assert self.store.count_active("owner-B") == 0

    def test_expired_members_pruned_on_read(self) -> None:
        real_now = __import__("time").time()
        self.store.track("owner-4", "tok-a", ttl=30)
        assert self.store.count_active("owner-4") == 1
        with mock.patch("tokenforge.tokens.onetime.time.time", return_value=real_now + 1000):
            assert self.store.count_active("owner-4") == 0

    def test_untrack_missing_is_noop(self) -> None:
        self.store.untrack("owner-none", "tok-x")  # must not raise
        assert self.store.count_active("owner-none") == 0

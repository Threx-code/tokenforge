"""v1.4 kill-switch tests — jti claim, access-token denylist, logout views (M2)."""

import time
from contextlib import contextmanager
from typing import Any

import pytest
from django.conf import settings as dj_settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIClient, APIRequestFactory

from tokenforge.security.authentication import BearerTokenAuthentication
from tokenforge.services.refresh import RefreshTokenService
from tokenforge.settings import reload_settings
from tokenforge.tokens import AccessToken, AccessTokenDenylist

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


@pytest.fixture(autouse=True)
def _clear_cache() -> Any:
    cache.clear()
    yield
    cache.clear()


@pytest.fixture()
def user(db: Any) -> Any:
    return User.objects.create_user(username="ks_user", password="pass")


# ── jti claim ─────────────────────────────────────────────────────────────────


class TestJtiClaim:
    def test_access_token_carries_unique_jti(self) -> None:
        t1, _ = AccessToken.create(user_id="u")
        t2, _ = AccessToken.create(user_id="u")
        p1, p2 = AccessToken.verify(t1), AccessToken.verify(t2)
        assert p1["jti"] and p2["jti"]
        assert p1["jti"] != p2["jti"]


# ── denylist primitive ────────────────────────────────────────────────────────


class TestDenylist:
    def test_denylist_then_check(self) -> None:
        AccessTokenDenylist.add("jti1", ttl=900)
        assert AccessTokenDenylist.contains("jti1") is True
        assert AccessTokenDenylist.contains("other") is False

    def test_empty_jti_is_noop(self) -> None:
        AccessTokenDenylist.add("", ttl=900)
        assert AccessTokenDenylist.contains("") is False

    def test_already_expired_is_noop(self) -> None:
        AccessTokenDenylist.add("jti0", ttl=0)
        assert AccessTokenDenylist.contains("jti0") is False
        AccessTokenDenylist.add("jtiX", exp=int(time.time()) - 10)
        assert AccessTokenDenylist.contains("jtiX") is False


# ── auth-path enforcement ─────────────────────────────────────────────────────


class TestDenylistAuth:
    def test_denylisted_token_is_rejected(self, user: Any) -> None:
        token, _ = AccessToken.create(user_id=str(user.id))
        jti = AccessToken.verify(token)["jti"]
        factory = APIRequestFactory()
        auth = BearerTokenAuthentication()

        with tf_settings(ACCESS_TOKEN_DENYLIST_ENABLED=True):
            # Not denylisted yet → authenticates.
            req = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
            assert auth.authenticate(req) is not None
            # Denylist it → now rejected.
            AccessTokenDenylist.add(str(jti), ttl=900)
            req2 = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
            with pytest.raises(AuthenticationFailed):
                auth.authenticate(req2)

    def test_denylist_ignored_when_disabled(self, user: Any) -> None:
        token, _ = AccessToken.create(user_id=str(user.id))
        AccessTokenDenylist.add(str(AccessToken.verify(token)["jti"]), ttl=900)
        # Denylist disabled (default) → the token still authenticates.
        req = APIRequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
        assert BearerTokenAuthentication().authenticate(req) is not None


# ── logout views ──────────────────────────────────────────────────────────────


class TestLogoutView:
    url = "/api/v1/auth/logout/"

    def test_revokes_refresh_family_and_clears_cookie(self, user: Any) -> None:
        client = APIClient()
        raw, instance = RefreshTokenService.create(user=user, fingerprint="")
        client.cookies["refresh_token"] = raw
        resp = client.post(self.url)
        assert resp.status_code == 204
        instance.refresh_from_db()
        assert instance.revoked is True

    def test_denylists_bearer_when_enabled(self, user: Any) -> None:
        client = APIClient()
        access, _ = AccessToken.create(user_id=str(user.id))
        jti = AccessToken.verify(access)["jti"]
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        with tf_settings(ACCESS_TOKEN_DENYLIST_ENABLED=True):
            resp = client.post(self.url)
            assert resp.status_code == 204
            assert AccessTokenDenylist.contains(str(jti)) is True


class TestLogoutAllView:
    url = "/api/v1/auth/logout-all/"

    def test_requires_authentication(self) -> None:
        resp = APIClient().post(self.url)
        assert resp.status_code in (401, 403)

    def test_revokes_all_refresh_tokens(self, user: Any) -> None:
        client = APIClient()
        _r1, t1 = RefreshTokenService.create(user=user, fingerprint="")
        _r2, t2 = RefreshTokenService.create(user=user, fingerprint="")
        access, _ = AccessToken.create(user_id=str(user.id), device_session_id="s")
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        resp = client.post(self.url)
        assert resp.status_code == 204
        t1.refresh_from_db()
        t2.refresh_from_db()
        assert t1.revoked and t2.revoked

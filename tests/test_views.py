"""
Tests for tokenforge views — TokenRefreshView, ExchangeCreateView, ExchangeRedeemView.
"""

from contextlib import contextmanager

import pytest
from django.conf import settings as dj_settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APIClient

from tokenforge.services.exchange import ExchangeTokenService
from tokenforge.services.refresh import RefreshTokenService
from tokenforge.settings import reload_settings
from tokenforge.tokens import AccessToken

User = get_user_model()
pytestmark = pytest.mark.django_db


# ── Fixtures ──────────────────────────────────────────────────────────────────


@contextmanager
def tf_settings(**overrides):
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
def clear_cache():
    # Allowlist the test origin — exchange creation is fail-closed (2.0) when
    # EXCHANGE_ALLOWED_ORIGINS is unset.
    cache.clear()
    with tf_settings(EXCHANGE_ALLOWED_ORIGINS=["https://app.example.com"]):
        yield
    cache.clear()


@pytest.fixture()
def user(db):
    return User.objects.create_user(username="view_user", password="pass", email="view@example.com")


@pytest.fixture()
def client():
    return APIClient()


@pytest.fixture()
def auth_client(user):
    """APIClient with a valid Bearer token for the test user."""
    client = APIClient()
    access_token, _ = AccessToken.create(
        user_id=str(user.id),
        device_session_id="sess-view-test",
        fingerprint="",
    )
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    return client, user


@pytest.fixture()
def refresh_cookie_client(user):
    """APIClient with a valid refresh_token cookie set."""
    client = APIClient()
    raw_token, _ = RefreshTokenService.create(user=user, fingerprint="")
    client.cookies["refresh_token"] = raw_token
    return client, user, raw_token


# ── TokenRefreshView ──────────────────────────────────────────────────────────


class TestTokenRefreshView:
    url = "/api/v1/auth/token/refresh/"

    def _post(self, client, xhr=True, cookie=None, **extra):
        if cookie:
            client.cookies["refresh_token"] = cookie
        headers = {}
        if xhr:
            headers["HTTP_X_REQUESTED_WITH"] = "XMLHttpRequest"
        return client.post(self.url, **headers, **extra)

    def test_valid_token_returns_200_with_access_token(self, refresh_cookie_client):
        client, user, raw_token = refresh_cookie_client
        response = self._post(client)
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "expires_in" in data
        assert data["expires_in"] > 0

    def test_valid_token_sets_new_refresh_cookie(self, refresh_cookie_client):
        client, user, raw_token = refresh_cookie_client
        response = self._post(client)
        assert response.status_code == 200
        assert "refresh_token" in response.cookies

    def test_missing_cookie_returns_401(self, client):
        response = client.post(self.url, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        assert response.status_code == 401

    def test_invalid_cookie_returns_401(self, client):
        client.cookies["refresh_token"] = "not-a-real-token"
        response = client.post(self.url, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        assert response.status_code == 401

    def test_missing_xhr_header_returns_403(self, refresh_cookie_client):
        client, user, raw_token = refresh_cookie_client
        # Post without the XHR header
        response = client.post(self.url)
        assert response.status_code == 403

    def test_oversized_cookie_returns_401(self, client):
        client.cookies["refresh_token"] = "x" * 513
        response = client.post(self.url, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        assert response.status_code == 401

    def test_expired_cookie_returns_401(self, user):
        from django.utils import timezone

        raw_token, instance = RefreshTokenService.create(user=user)
        instance.expires_at = timezone.now() - timezone.timedelta(seconds=1)
        instance.save(update_fields=["expires_at"])
        client = APIClient()
        client.cookies["refresh_token"] = raw_token
        response = client.post(self.url, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        assert response.status_code == 401

    def test_second_use_of_same_token_returns_401(self, refresh_cookie_client):
        """Replay: using the same token twice should be rejected on second attempt."""
        client, user, raw_token = refresh_cookie_client
        # First rotation succeeds
        r1 = self._post(client)
        assert r1.status_code == 200
        # Replay with the original token (client still has it in the cookie fixture var)
        client.cookies["refresh_token"] = raw_token
        r2 = self._post(client)
        assert r2.status_code == 401

    def test_invalid_token_expires_cookie(self, client):
        """On failure the expired Set-Cookie must clear the cookie."""
        client.cookies["refresh_token"] = "bad-token"
        response = client.post(self.url, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        assert response.status_code == 401
        # The response should clear the refresh_token cookie (max_age=0 or expires in past)
        cookie = response.cookies.get("refresh_token")
        if cookie:
            assert cookie["max-age"] == 0 or cookie.value == ""


# ── ExchangeCreateView ────────────────────────────────────────────────────────


class TestExchangeCreateView:
    url = "/api/v1/auth/exchange/create/"

    def test_authenticated_user_gets_exchange_token(self, auth_client):
        client, user = auth_client
        response = client.post(
            self.url,
            {"target_origin": "https://app.example.com"},
            format="json",
        )
        assert response.status_code == 200
        data = response.json()
        assert "exchange_token" in data
        assert "ttl" in data
        assert data["ttl"] > 0

    def test_unauthenticated_request_returns_401(self, client):
        response = client.post(
            self.url,
            {"target_origin": "https://app.example.com"},
            format="json",
        )
        assert response.status_code == 401

    def test_missing_target_origin_returns_400(self, auth_client):
        client, user = auth_client
        response = client.post(self.url, {}, format="json")
        assert response.status_code == 400

    def test_exchange_token_is_redeemable(self, auth_client):
        """The returned exchange token must be redeemable for auth context."""
        client, user = auth_client
        resp = client.post(
            self.url,
            {"target_origin": "https://app.example.com"},
            format="json",
        )
        assert resp.status_code == 200
        token = resp.json()["exchange_token"]

        from tokenforge.services.exchange import ExchangeTokenService

        payload = ExchangeTokenService.redeem(token=token, request_origin="https://app.example.com")
        assert payload["sub"] == str(user.id)

    def test_too_many_tokens_returns_429(self, auth_client):
        """A second create while one token is already active (cap=1) → 429."""
        client, user = auth_client
        with tf_settings(
            EXCHANGE_ALLOWED_ORIGINS=["https://app.example.com"],
            EXCHANGE_TOKEN_MAX_ACTIVE=1,
        ):
            r1 = client.post(self.url, {"target_origin": "https://app.example.com"}, format="json")
            assert r1.status_code == 200  # count → 1
            r2 = client.post(self.url, {"target_origin": "https://app.example.com"}, format="json")
            assert r2.status_code == 429  # count 1 >= cap 1


# ── ExchangeRedeemView ────────────────────────────────────────────────────────


class TestExchangeRedeemView:
    url = "/api/v1/auth/exchange/redeem/"

    def _create_token(self, user_id, target_origin="https://app.example.com"):
        return ExchangeTokenService.create(
            user_id=str(user_id),
            device_session_id="sess-redeem",
            fingerprint="",
            target_origin=target_origin,
        )

    def test_valid_token_returns_200_with_access_token(self, user, client):
        token = self._create_token(user.id)
        response = client.post(
            self.url,
            {"exchange_token": token},
            format="json",
            HTTP_ORIGIN="https://app.example.com",
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "expires_in" in data

    def test_valid_token_sets_refresh_cookie(self, user, client):
        token = self._create_token(user.id)
        response = client.post(
            self.url,
            {"exchange_token": token},
            format="json",
            HTTP_ORIGIN="https://app.example.com",
        )
        assert response.status_code == 200
        assert "refresh_token" in response.cookies

    def test_invalid_token_returns_401(self, client):
        response = client.post(
            self.url,
            {"exchange_token": "not-valid"},
            format="json",
            HTTP_ORIGIN="https://app.example.com",
        )
        assert response.status_code == 401

    def test_missing_token_returns_400(self, client):
        response = client.post(self.url, {}, format="json")
        assert response.status_code == 400

    def test_origin_mismatch_returns_401(self, user, client):
        token = self._create_token(user.id, target_origin="https://app.example.com")
        response = client.post(
            self.url,
            {"exchange_token": token},
            format="json",
            HTTP_ORIGIN="https://evil.example.com",
        )
        assert response.status_code == 401

    def test_nonexistent_user_returns_401(self, client):
        # Use an integer ID that is unlikely to exist in the test DB
        fake_uid = "99999999"
        token = ExchangeTokenService.create(
            user_id=fake_uid,
            device_session_id="s1",
            fingerprint="",
            target_origin="https://app.example.com",
        )
        response = client.post(
            self.url,
            {"exchange_token": token},
            format="json",
            HTTP_ORIGIN="https://app.example.com",
        )
        assert response.status_code == 401

    def test_second_use_of_same_token_returns_401(self, user, client):
        token = self._create_token(user.id)
        r1 = client.post(
            self.url,
            {"exchange_token": token},
            format="json",
            HTTP_ORIGIN="https://app.example.com",
        )
        assert r1.status_code == 200
        r2 = client.post(
            self.url,
            {"exchange_token": token},
            format="json",
            HTTP_ORIGIN="https://app.example.com",
        )
        assert r2.status_code == 401

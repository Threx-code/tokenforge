"""Tests for MobileTokenRefreshView — body-based mobile refresh + platform guards."""

from contextlib import contextmanager
from typing import Any

import pytest
from django.conf import settings as dj_settings
from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APIClient, APIRequestFactory

from tokenforge.api.views import MobileTokenRefreshView
from tokenforge.services.refresh import RefreshTokenService
from tokenforge.settings import reload_settings

User = get_user_model()
pytestmark = pytest.mark.django_db

URL = "/api/v1/auth/mobile/token/refresh/"


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
    return User.objects.create_user(username="mob_user", password="pass")


def _post(
    client: APIClient, body: dict | None = None, *, platform: str | None = "mobile", **extra: Any
) -> Any:
    headers = {"HTTP_X_CLIENT_PLATFORM": platform} if platform is not None else {}
    # Deliberately no X-Requested-With — the mobile path must not require it.
    return client.post(URL, body or {}, format="json", **headers, **extra)


class TestMobileGuards:
    def test_non_mobile_platform_rejected(self, user: Any) -> None:
        raw, _ = RefreshTokenService.create(user=user, fingerprint="")
        resp = _post(APIClient(), {"refresh_token": raw}, platform=None)
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_wrong_platform_rejected(self, user: Any) -> None:
        raw, _ = RefreshTokenService.create(user=user, fingerprint="")
        resp = _post(APIClient(), {"refresh_token": raw}, platform="web")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_cookie_present_rejected(self, user: Any) -> None:
        # A genuine mobile client never sends the refresh cookie.
        client = APIClient()
        raw, _ = RefreshTokenService.create(user=user, fingerprint="")
        client.cookies["refresh_token"] = raw
        resp = _post(client, {"refresh_token": raw})
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_missing_body_token_returns_401(self, user: Any) -> None:
        resp = _post(APIClient(), {})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


class TestMobileHappyPath:
    def test_returns_token_in_body_and_sets_no_cookie(self, user: Any) -> None:
        raw, _ = RefreshTokenService.create(user=user, fingerprint="")
        resp = _post(APIClient(), {"refresh_token": raw})  # note: no X-Requested-With
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["access_token"]
        assert resp.data["refresh_token"]  # rotated token returned in the BODY
        assert resp.data["refresh_token"] != raw
        assert "refresh_token" not in resp.cookies  # and never as a Set-Cookie

    def test_strict_fingerprint_disabled_for_mobile(self, user: Any) -> None:
        # Global strict ON + a stored fingerprint that cannot match the request's
        # computed one → the web flow would 401; mobile must still succeed.
        raw, _ = RefreshTokenService.create(user=user, fingerprint="stored-fp-that-wont-match")
        with tf_settings(FINGERPRINT_STRICT_REFRESH=True):
            resp = _post(APIClient(), {"refresh_token": raw})
        assert resp.status_code == status.HTTP_200_OK


class TestMobilePreRotationGuard:
    def test_guard_can_reject_before_rotation(self, user: Any) -> None:
        class _Guarded(MobileTokenRefreshView):
            throttle_classes = []  # no throttle setup under APIRequestFactory

            def pre_rotation_guard(self, request: Any, raw_token: str) -> Any:
                return Response({"detail": "device mismatch"}, status=status.HTTP_401_UNAUTHORIZED)

        raw, _ = RefreshTokenService.create(user=user, fingerprint="")
        request = APIRequestFactory().post(
            URL, {"refresh_token": raw}, format="json", HTTP_X_CLIENT_PLATFORM="mobile"
        )
        resp = _Guarded.as_view()(request)
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

"""
TokenForge views — token refresh and cross-subdomain exchange endpoints.

Endpoints:
  POST /token/refresh/     — exchange refresh_token cookie for new tokens
  POST /exchange/create/   — create a one-time exchange token (requires auth)
  POST /exchange/redeem/   — redeem exchange token to get access + refresh tokens

All views use standard DRF GenericAPIView — no dependency on project-specific
base classes (GuestAPI, AuthAPI). Consuming apps can subclass and override.
"""

import contextlib
import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.db.models import Model
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from tokenforge.cookies import expire_refresh_cookie, set_refresh_cookie
from tokenforge.serializers import ExchangeCreateSerializer, ExchangeRedeemSerializer
from tokenforge.services.exchange import (
    count_active_exchange_tokens,
    create_exchange_token,
    increment_exchange_counter,
    redeem_exchange_token,
)
from tokenforge.services.refresh import create_refresh_token, rotate_refresh_token
from tokenforge.tokens import create_access_token

logger = logging.getLogger("tokenforge")


class TokenRefreshView(GenericAPIView[Model]):
    """
    Exchange a valid refresh_token cookie for a new access token + rotated refresh token.

    Request:
        POST /token/refresh/
        Cookie: refresh_token=<raw_token>
        Header: X-Requested-With: XMLHttpRequest (required, anti-CSRF)

    Response 200:
        {"access_token": "<new_access_token>", "expires_in": 900}
        Set-Cookie: refresh_token=<new_raw_token> (HttpOnly)
    """

    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "refresh_token"

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        from tokenforge.settings import tokenforge_settings

        # ── Anti-CSRF check ──────────────────────────────
        if tokenforge_settings.REQUIRE_XHR_HEADER:
            xhr_header = request.META.get("HTTP_X_REQUESTED_WITH", "")
            if xhr_header != "XMLHttpRequest":
                logger.warning("Token refresh: missing X-Requested-With header")
                return Response(
                    {"detail": "Authentication failed"},
                    status=status.HTTP_403_FORBIDDEN,
                )

        # ── Extract refresh token from cookie ────────────
        cookie_name = tokenforge_settings.REFRESH_TOKEN_COOKIE_NAME
        raw_token = request.COOKIES.get(cookie_name)
        if not raw_token:
            return Response(
                {"detail": "Session expired"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Guard against oversized cookie values (max expected: ~128 chars)
        if len(raw_token) > 512:
            logger.warning("Token refresh: oversized cookie value (%d bytes)", len(raw_token))
            return Response(
                {"detail": "Session expired"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # ── Compute current fingerprint ──────────────────
        fingerprint_fn = tokenforge_settings.FINGERPRINT_FUNCTION
        fingerprint = fingerprint_fn(request) if fingerprint_fn else ""

        # ── Rotate refresh token ─────────────────────────
        try:
            new_raw_token, new_instance = rotate_refresh_token(
                raw_token=raw_token,
                fingerprint=fingerprint,
                request=request,
            )
        except ValueError as e:
            logger.warning("Token refresh failed: %s", str(e))
            response = Response(
                {"detail": "Session expired"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
            expire_refresh_cookie(response)
            return response

        # ── Create new access token ──────────────────────
        device_session = getattr(new_instance, "device_session", None)
        tenant_slug = request.META.get("HTTP_X_TENANT_SLUG", "")

        access_token, expires_in = create_access_token(
            user_id=str(new_instance.user_id),
            device_session_id=str(device_session.id) if device_session else "",
            fingerprint=fingerprint,
            tenant_slug=tenant_slug,
        )

        # ── Build response ───────────────────────────────
        response = Response(
            {
                "access_token": access_token,
                "expires_in": expires_in,
            },
            status=status.HTTP_200_OK,
        )

        set_refresh_cookie(response, new_raw_token)
        return response


class ExchangeCreateView(GenericAPIView[Model]):
    """
    Create a one-time exchange token for cross-subdomain navigation.

    Request:
        POST /exchange/create/
        Authorization: Bearer <access_token>
        Body: {"target_origin": "http://cashra.localhost:5173"}

    Response 200:
        {"exchange_token": "<token>", "ttl": 60}
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "request_rate"

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        from tokenforge.settings import tokenforge_settings

        serializer = ExchangeCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        target_origin = serializer.validated_data["target_origin"]
        user_id = str(request.user.id)

        # ── Rate limit: max concurrent exchange tokens ───
        max_active = tokenforge_settings.EXCHANGE_TOKEN_MAX_ACTIVE
        active_count = count_active_exchange_tokens(user_id)
        if active_count >= max_active:
            return Response(
                {"detail": "Too many pending exchange tokens"},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # ── Get session from auth context ────────────────
        auth_context: dict[str, Any] = request.auth if isinstance(request.auth, dict) else {}
        device_session_id = str(auth_context.get("sid", ""))
        fingerprint = str(auth_context.get("fp", ""))

        # ── Create exchange token ────────────────────────
        token = create_exchange_token(
            user_id=user_id,
            device_session_id=device_session_id,
            fingerprint=fingerprint,
            target_origin=target_origin,
        )
        increment_exchange_counter(user_id)

        return Response(
            {
                "exchange_token": token,
                "ttl": tokenforge_settings.EXCHANGE_TOKEN_TTL_SECONDS,
            },
            status=status.HTTP_200_OK,
        )


class ExchangeRedeemView(GenericAPIView[Model]):
    """
    Redeem a one-time exchange token to get access + refresh tokens.

    Request:
        POST /exchange/redeem/
        Body: {"exchange_token": "<token>"}

    Response 200:
        {
            "access_token": "<token>",
            "expires_in": 900,
            "user": {...}
        }
        Set-Cookie: refresh_token=<raw_token> (HttpOnly)
    """

    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "request_rate"

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        from tokenforge.settings import tokenforge_settings

        serializer = ExchangeRedeemSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        exchange_token = serializer.validated_data["exchange_token"]

        # ── Get request origin for binding check ─────────
        # Use the Origin header only — it is set by browsers on all cross-origin
        # requests and cannot be forged by page content (unlike Referer).
        # Referer is intentionally excluded: it includes the full path (leaks
        # sensitive URL params), is not sent in all cases, and is not a security
        # boundary. An absent Origin header is treated as a mismatch by
        # redeem_exchange_token() when a target_origin is set.
        request_origin = request.META.get("HTTP_ORIGIN", "")

        # ── Redeem the exchange token ────────────────────
        try:
            payload = redeem_exchange_token(
                token=exchange_token,
                request_origin=request_origin,
            )
        except ValueError as e:
            logger.warning("Exchange redeem failed: %s", str(e))
            return Response(
                {"detail": "Authentication failed"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        user_id = payload["sub"]
        device_session_id = payload.get("sid", "")

        # ── Load user ────────────────────────────────────
        User = get_user_model()
        try:
            user = User.objects.get(id=user_id, is_active=True)
        except User.DoesNotExist:
            return Response(
                {"detail": "Authentication failed"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # ── Load device session (via configurable callback) ──
        device_session = None
        if device_session_id:
            loader = tokenforge_settings.DEVICE_SESSION_LOADER
            if loader:
                with contextlib.suppress(
                    Exception
                ):  # Device session loading failure shouldn't block auth
                    device_session = loader(device_session_id, user)

        # ── Compute fingerprint ──────────────────────────
        fingerprint_fn = tokenforge_settings.FINGERPRINT_FUNCTION
        fingerprint = fingerprint_fn(request) if fingerprint_fn else ""

        # ── Create new refresh token ─────────────────────
        raw_refresh, refresh_instance = create_refresh_token(
            user=user,
            device_session=device_session,
            fingerprint=fingerprint,
        )

        # ── Create access token ──────────────────────────
        tenant_slug = request.META.get("HTTP_X_TENANT_SLUG", "")

        access_token, expires_in = create_access_token(
            user_id=str(user.id),
            device_session_id=str(device_session.id) if device_session else "",
            fingerprint=fingerprint,
            tenant_slug=tenant_slug,
        )

        # ── Build response ───────────────────────────────
        response_data = {
            "access_token": access_token,
            "expires_in": expires_in,
        }

        # Serialize user if a USER_SERIALIZER is configured
        user_serializer_class = tokenforge_settings.USER_SERIALIZER
        if user_serializer_class:
            response_data["user"] = user_serializer_class(user).data

        response = Response(response_data, status=status.HTTP_200_OK)
        set_refresh_cookie(response, raw_refresh)
        return response

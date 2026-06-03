"""Cross-subdomain SSO handoff — create and redeem one-time exchange tokens."""

import contextlib
from typing import Any

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from tokenforge.api.serializers import ExchangeCreateSerializer, ExchangeRedeemSerializer
from tokenforge.api.views.base import BaseTokenView, logger
from tokenforge.security import RefreshCookie
from tokenforge.services.exchange import ExchangeTokenService
from tokenforge.services.refresh import RefreshTokenService
from tokenforge.tokens import AccessToken


class ExchangeCreateView(BaseTokenView):
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
        if ExchangeTokenService.count_active(user_id) >= max_active:
            return Response(
                {"detail": "Too many pending exchange tokens"},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # ── Get session from auth context ────────────────
        auth_context: dict[str, Any] = request.auth if isinstance(request.auth, dict) else {}
        device_session_id = str(auth_context.get("sid", ""))
        fingerprint = str(auth_context.get("fp", ""))

        # ── Create exchange token ────────────────────────
        # ExchangeTokenService.create raises ValueError when the target origin is
        # not on EXCHANGE_ALLOWED_ORIGINS (2.0 fail-closed when unset). Surface
        # that as a 403 rather than a 500.
        try:
            token = ExchangeTokenService.create(
                user_id=user_id,
                device_session_id=device_session_id,
                fingerprint=fingerprint,
                target_origin=target_origin,
            )
        except ValueError as e:
            logger.warning("Exchange create rejected: %s", str(e))
            return Response(
                {"detail": "Exchange target origin is not allowed"},
                status=status.HTTP_403_FORBIDDEN,
            )

        return Response(
            {
                "exchange_token": token,
                "ttl": tokenforge_settings.EXCHANGE_TOKEN_TTL_SECONDS,
            },
            status=status.HTTP_200_OK,
        )


class ExchangeRedeemView(BaseTokenView):
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
        # ExchangeTokenService.redeem() when a target_origin is set.
        request_origin = request.META.get("HTTP_ORIGIN", "")
        request_fingerprint = self.request_fingerprint(request)

        # ── Redeem the exchange token ────────────────────
        try:
            payload = ExchangeTokenService.redeem(
                token=exchange_token,
                request_origin=request_origin,
                request_fingerprint=request_fingerprint,
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
        fingerprint = self.request_fingerprint(request)

        # ── Create new refresh token ─────────────────────
        raw_refresh, refresh_instance = RefreshTokenService.create(
            user=user,
            device_session=device_session,
            fingerprint=fingerprint,
        )

        # ── Create access token ──────────────────────────
        tenant_slug = self.resolve_tenant(request, user)

        access_token, expires_in = AccessToken.create(
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
        RefreshCookie(response).set(raw_refresh)
        return response

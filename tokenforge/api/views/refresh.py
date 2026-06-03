"""Web refresh endpoint — exchange the refresh_token cookie for new tokens."""

from typing import Any

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from tokenforge.api.views.base import BaseTokenView, logger
from tokenforge.security import RefreshCookie
from tokenforge.services.refresh import RefreshTokenService
from tokenforge.tokens import AccessToken


class TokenRefreshView(BaseTokenView):
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

    # Per-view fingerprint-strictness override (None = use FINGERPRINT_STRICT_REFRESH).
    # Subclass and set False for the mobile refresh path: mobile IP/UA is not
    # stable, and mobile binds on the device session / device id instead, so a
    # fingerprint mismatch must not log the user out. See docs/v2-hardening.md.
    strict_fingerprint: bool | None = None

    # Per-view anti-CSRF override (None = use REQUIRE_XHR_HEADER). The
    # X-Requested-With requirement defends the cookie-based web flow; the mobile
    # flow carries the token in the body (no ambient cookie → no CSRF surface),
    # so MobileTokenRefreshView sets this False.
    require_xhr_header: bool | None = None

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        from tokenforge.settings import tokenforge_settings

        # ── Anti-CSRF check ──────────────────────────────
        require_xhr = (
            self.require_xhr_header
            if self.require_xhr_header is not None
            else tokenforge_settings.REQUIRE_XHR_HEADER
        )
        if require_xhr:
            xhr_header = request.META.get("HTTP_X_REQUESTED_WITH", "")
            if xhr_header != "XMLHttpRequest":
                logger.warning("Token refresh: missing X-Requested-With header")
                return Response(
                    {"detail": "Authentication failed"},
                    status=status.HTTP_403_FORBIDDEN,
                )

        # ── Extract refresh token from cookie ────────────
        cookie_name = RefreshCookie.name()
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
        fingerprint = self.request_fingerprint(request)

        # ── Rotate refresh token ─────────────────────────
        try:
            new_raw_token, new_instance = RefreshTokenService.rotate(
                raw_token=raw_token,
                fingerprint=fingerprint,
                request=request,
                strict_fingerprint=self.strict_fingerprint,
            )
        except ValueError as e:
            logger.warning("Token refresh failed: %s", str(e))
            response = Response(
                {"detail": "Session expired"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
            RefreshCookie(response).expire()
            return response

        # ── Create new access token ──────────────────────
        device_session = getattr(new_instance, "device_session", None)
        tenant_slug = self.resolve_tenant(request, new_instance.user)

        access_token, expires_in = AccessToken.create(
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

        RefreshCookie(response).set(new_raw_token)
        return response

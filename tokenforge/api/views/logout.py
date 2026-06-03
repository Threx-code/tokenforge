"""Logout endpoints — single-session and all-session revocation."""

import contextlib
from typing import Any

from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from tokenforge.api.views.base import BaseTokenView
from tokenforge.security import RefreshCookie
from tokenforge.security.authentication import BearerTokenAuthentication
from tokenforge.services.refresh import RefreshTokenService
from tokenforge.tokens import AccessToken, AccessTokenDenylist


class LogoutView(BaseTokenView):
    """Single-session logout.

    Revokes this session's refresh-token family and (if the denylist is enabled)
    denylists the presented access token's ``jti`` so it can't be used for its
    remaining lifetime. Clears the refresh cookie. The refresh token is taken
    from the cookie (web) or the request body (mobile). Idempotent — always 204.
    """

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "refresh_token"
    body_token_field = "refresh_token"

    @staticmethod
    def _denylist_bearer(request: Request) -> None:
        """If the denylist is enabled and a valid Bearer access token is present,
        revoke it by ``jti`` for its remaining lifetime. Best-effort."""
        from tokenforge.settings import tokenforge_settings

        if not tokenforge_settings.ACCESS_TOKEN_DENYLIST_ENABLED:
            return
        auth = request.META.get("HTTP_AUTHORIZATION", "")
        parts = auth.split(" ", 1)
        if len(parts) != 2 or parts[0] != "Bearer":
            return
        with contextlib.suppress(Exception):
            payload = AccessToken.verify(parts[1].strip())
            exp = payload.get("exp")
            AccessTokenDenylist.add(
                str(payload.get("jti", "")), exp=exp if isinstance(exp, int) else None
            )

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        self._denylist_bearer(request)

        raw_refresh = (
            request.COOKIES.get(RefreshCookie.name())
            or str(request.data.get(self.body_token_field) or "").strip()
        )
        if raw_refresh:
            with contextlib.suppress(Exception):
                RefreshTokenService.revoke_by_raw_token(raw_refresh, reason="logout")

        response = Response(status=status.HTTP_204_NO_CONTENT)
        RefreshCookie(response).expire()
        return response


class LogoutAllView(BaseTokenView):
    """All-session logout for the authenticated user.

    Revokes every refresh token (no new access tokens can be minted) and
    denylists the current access token. Other sessions' access tokens expire
    within their lifetime. Requires a valid Bearer access token.
    """

    authentication_classes = [BearerTokenAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "refresh_token"

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        from tokenforge.settings import tokenforge_settings

        RefreshTokenService.revoke_all_for_user(request.user)

        if tokenforge_settings.ACCESS_TOKEN_DENYLIST_ENABLED and isinstance(request.auth, dict):
            AccessTokenDenylist.add(str(request.auth.get("jti", "")), exp=request.auth.get("exp"))

        response = Response(status=status.HTTP_204_NO_CONTENT)
        RefreshCookie(response).expire()
        return response

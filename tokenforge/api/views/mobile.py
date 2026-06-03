"""Native mobile refresh — body-based token, platform-guarded, no ambient cookie."""

from typing import Any

from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response

from tokenforge.api.views.refresh import TokenRefreshView
from tokenforge.security import RefreshCookie


class MobileClientMixin:
    """Guards that ensure only a genuine mobile client reaches a view.

    A mobile client identifies itself with the ``X-Client-Platform: mobile``
    header and MUST NOT send the refresh cookie — it carries the refresh token
    in the request body and persists it in secure device storage. Rejecting any
    request that presents the cookie keeps the cookie/CSRF surface of the web
    flow off the mobile endpoint.
    """

    platform_header = "X-Client-Platform"
    platform_value = "mobile"

    def reject_non_mobile(self, request: Request) -> Response | None:
        """Return a 400 Response if the request is not a cookie-less mobile
        client, else None."""
        platform = request.headers.get(self.platform_header, "").strip().lower()
        if platform != self.platform_value:
            return Response(
                {"detail": "Mobile client required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if request.COOKIES.get(RefreshCookie.name()):
            # A real mobile client never sends the refresh cookie.
            return Response(
                {"detail": "Unexpected credential."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return None


class MobileTokenRefreshView(MobileClientMixin, TokenRefreshView):
    """Body-based refresh for native mobile clients.

    Differences from the web ``TokenRefreshView``:
      - the refresh token is read from the request BODY (secure storage), not a
        cookie, and the rotated token is returned in the response BODY;
      - a platform guard ensures only a cookie-less mobile client reaches it;
      - X-Requested-With is not required (no ambient cookie → no CSRF surface);
      - fingerprint hard-fail is OFF — mobile IP/UA is unstable; bind on the
        device session instead (see ``pre_rotation_guard`` and the
        ``DEVICE_SESSION_VALIDATOR`` callback).

    The full rotation pipeline (replay detection, device-session validation,
    rotation) still runs, identical to the web flow.

    **Device binding is intentionally a hook.** Matching a device-id header
    against the session, integrity attestation, audit, etc. depend on YOUR
    device-session schema and stay in your project: subclass and override
    ``pre_rotation_guard`` to enforce them.
    """

    strict_fingerprint = False
    require_xhr_header = False
    body_token_field = "refresh_token"

    def pre_rotation_guard(self, request: Request, raw_token: str) -> Response | None:
        """Hook run before rotation. Return a Response to reject (e.g. on a
        device-id / integrity mismatch), or None to proceed. Default: no-op."""
        return None

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        if (err := self.reject_non_mobile(request)) is not None:
            return err

        raw_token = str(request.data.get(self.body_token_field) or "").strip()
        if not raw_token:
            return Response({"detail": "Session expired"}, status=status.HTTP_401_UNAUTHORIZED)

        if (err := self.pre_rotation_guard(request, raw_token)) is not None:
            return err

        # Present the body token as the cookie the parent pipeline expects, so
        # replay detection / session validation / rotation run identically.
        cookie_name = RefreshCookie.name()
        request.COOKIES[cookie_name] = raw_token

        response = super().post(request, *args, **kwargs)

        # Return the rotated token in the body and strip every Set-Cookie —
        # mobile persists the token itself, and must not receive a cookie.
        new_cookie = response.cookies.get(cookie_name)
        if response.status_code == status.HTTP_200_OK and new_cookie:
            response.data = {**response.data, self.body_token_field: new_cookie.value}
        if cookie_name in response.cookies:
            del response.cookies[cookie_name]
        return response

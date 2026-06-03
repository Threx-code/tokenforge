"""
TokenForge refresh cookie — set/expire the refresh_token HttpOnly cookie.

Usage:
    RefreshCookie(response).set(raw_token)
    RefreshCookie(response).expire()
    RefreshCookie.name()   # the effective wire name (with `__Secure-` prefix)
"""

from rest_framework.response import Response


class RefreshCookie:
    """The refresh-token cookie on a given response (the response is the state)."""

    # Cookie-name prefix that instructs the browser to reject the cookie unless it
    # was set Secure (over HTTPS). See USE_SECURE_COOKIE_PREFIX.
    _SECURE_PREFIX = "__Secure-"

    def __init__(self, response: Response) -> None:
        self.response = response

    @classmethod
    def name(cls) -> str:
        """The wire name of the refresh cookie.

        When USE_SECURE_COOKIE_PREFIX is on AND the cookie is Secure, the
        configured name is prefixed with ``__Secure-`` (defence in depth). The
        prefix is only valid on a Secure cookie, so it is skipped when
        REFRESH_TOKEN_COOKIE_SECURE is False (local HTTP dev) — otherwise the
        browser would silently drop it.

        Every site that reads or writes the cookie MUST use this name so the
        prefixed and un-prefixed worlds never disagree.
        """
        from tokenforge.settings import tokenforge_settings

        name = str(tokenforge_settings.REFRESH_TOKEN_COOKIE_NAME)
        if (
            tokenforge_settings.USE_SECURE_COOKIE_PREFIX
            and tokenforge_settings.REFRESH_TOKEN_COOKIE_SECURE
        ):
            return f"{cls._SECURE_PREFIX}{name}"
        return name

    def set(self, raw_token: str) -> None:
        """Set the refresh_token HttpOnly cookie with tight scoping."""
        from tokenforge.settings import tokenforge_settings

        self.response.set_cookie(
            key=self.name(),
            value=raw_token,
            httponly=True,
            secure=tokenforge_settings.REFRESH_TOKEN_COOKIE_SECURE,
            samesite=tokenforge_settings.REFRESH_TOKEN_COOKIE_SAMESITE,
            path=tokenforge_settings.REFRESH_TOKEN_COOKIE_PATH,
            max_age=tokenforge_settings.REFRESH_TOKEN_LIFETIME_DAYS * 86400,
            domain=tokenforge_settings.REFRESH_TOKEN_COOKIE_DOMAIN,
        )

    def expire(self) -> None:
        """Expire the refresh_token cookie."""
        from tokenforge.settings import tokenforge_settings

        self.response.set_cookie(
            key=self.name(),
            value="",
            max_age=0,
            httponly=True,
            secure=tokenforge_settings.REFRESH_TOKEN_COOKIE_SECURE,
            samesite=tokenforge_settings.REFRESH_TOKEN_COOKIE_SAMESITE,
            path=tokenforge_settings.REFRESH_TOKEN_COOKIE_PATH,
            domain=tokenforge_settings.REFRESH_TOKEN_COOKIE_DOMAIN,
        )

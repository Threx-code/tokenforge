"""
TokenForge cookie helpers — set and expire the refresh_token HttpOnly cookie.

Usage:
    from tokenforge.cookies import set_refresh_cookie, expire_refresh_cookie

    set_refresh_cookie(response, raw_token)
    expire_refresh_cookie(response)
"""

from rest_framework.response import Response


def set_refresh_cookie(response: Response, raw_token: str) -> None:
    """Set the refresh_token HttpOnly cookie with tight scoping."""
    from tokenforge.settings import tokenforge_settings

    response.set_cookie(
        key=tokenforge_settings.REFRESH_TOKEN_COOKIE_NAME,
        value=raw_token,
        httponly=True,
        secure=tokenforge_settings.REFRESH_TOKEN_COOKIE_SECURE,
        samesite=tokenforge_settings.REFRESH_TOKEN_COOKIE_SAMESITE,
        path=tokenforge_settings.REFRESH_TOKEN_COOKIE_PATH,
        max_age=tokenforge_settings.REFRESH_TOKEN_LIFETIME_DAYS * 86400,
        domain=tokenforge_settings.REFRESH_TOKEN_COOKIE_DOMAIN,
    )


def expire_refresh_cookie(response: Response) -> None:
    """Expire the refresh_token cookie."""
    from tokenforge.settings import tokenforge_settings

    response.set_cookie(
        key=tokenforge_settings.REFRESH_TOKEN_COOKIE_NAME,
        value="",
        max_age=0,
        httponly=True,
        secure=tokenforge_settings.REFRESH_TOKEN_COOKIE_SECURE,
        samesite=tokenforge_settings.REFRESH_TOKEN_COOKIE_SAMESITE,
        path=tokenforge_settings.REFRESH_TOKEN_COOKIE_PATH,
        domain=tokenforge_settings.REFRESH_TOKEN_COOKIE_DOMAIN,
    )

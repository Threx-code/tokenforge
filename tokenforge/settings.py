"""
TokenForge settings — knox-style configuration via a single TOKENFORGE dict.

Usage in Django settings:
    TOKENFORGE = {
        "ACCESS_TOKEN_LIFETIME_SECONDS": 900,
        "TOKEN_MODEL": "myapp.MyRefreshToken",
        "RISK_EVENT_HANDLER": "myapp.services.log_risk_event",
        ...
    }

Access in code:
    from tokenforge.settings import tokenforge_settings
    ttl = tokenforge_settings.ACCESS_TOKEN_LIFETIME_SECONDS
"""

from django.conf import settings
from rest_framework.settings import APISettings

DEFAULTS = {
    # ── Access Token ─────────────────────────────────────
    "ACCESS_TOKEN_LIFETIME_SECONDS": 900,  # 15 minutes
    "ACCESS_TOKEN_SIGNING_KEY": None,  # Required — must be set explicitly, no fallback
    # ── Refresh Token ────────────────────────────────────
    "REFRESH_TOKEN_LIFETIME_DAYS": 30,
    "REFRESH_TOKEN_BYTES": 48,  # 384 bits of entropy
    "REFRESH_TOKEN_COOKIE_NAME": "refresh_token",
    "REFRESH_TOKEN_COOKIE_PATH": "/api/v1/auth/token/refresh/",
    "REFRESH_TOKEN_COOKIE_SECURE": True,  # Secure by default; set False only for local dev
    "REFRESH_TOKEN_COOKIE_SAMESITE": "Lax",
    "REFRESH_TOKEN_COOKIE_DOMAIN": None,  # None = host-only; set to ".example.com" for cross-subdomain
    "TOKEN_MODEL": "tokenforge.RefreshToken",
    # ── Exchange Token ───────────────────────────────────
    "EXCHANGE_TOKEN_TTL_SECONDS": 60,
    "EXCHANGE_TOKEN_BYTES": 48,
    "EXCHANGE_TOKEN_MAX_ACTIVE": 5,
    # ── Security ─────────────────────────────────────────
    "FINGERPRINT_ENABLED": True,
    # Soft-warn on access token fingerprint drift (default).
    # Set True only if your deployment has stable, trusted client IPs
    # (e.g. internal tools behind a VPN). Mobile/SPA users will get spurious
    # logouts if enabled. Hard-fail is always enforced at refresh token rotation.
    "FINGERPRINT_STRICT_ACCESS_TOKEN": False,
    "REPLAY_DETECTION_ENABLED": True,
    "RISK_SCORE_THRESHOLD": 60,
    "BOT_SCORE_THRESHOLD": 90,
    "USER_CACHE_TTL": 300,  # 5 minutes
    # ── Callbacks (dotted import paths, optional) ────────
    "RISK_EVENT_HANDLER": None,
    "DEVICE_SESSION_VALIDATOR": None,  # fn(device_session) -> None or raises
    "DEVICE_SESSION_LOADER": None,  # fn(session_id, user) -> session or None
    "USER_SERIALIZER": None,
    "FINGERPRINT_FUNCTION": "tokenforge.fingerprinting.fingerprint_for_request",
    # ── Anti-CSRF ────────────────────────────────────────
    "REQUIRE_XHR_HEADER": True,
}

# Settings that should be imported from strings when accessed
IMPORT_STRINGS = [
    "RISK_EVENT_HANDLER",
    "DEVICE_SESSION_VALIDATOR",
    "DEVICE_SESSION_LOADER",
    "USER_SERIALIZER",
    "FINGERPRINT_FUNCTION",
]

tokenforge_settings = APISettings(
    user_settings=getattr(settings, "TOKENFORGE", {}),  # type: ignore[arg-type]
    defaults=DEFAULTS,  # type: ignore[arg-type]
    import_strings=IMPORT_STRINGS,
)


def reload_settings() -> None:
    """Reload settings (useful for testing)."""
    global tokenforge_settings
    tokenforge_settings = APISettings(
        user_settings=getattr(settings, "TOKENFORGE", {}),  # type: ignore[arg-type]
        defaults=DEFAULTS,  # type: ignore[arg-type]
        import_strings=IMPORT_STRINGS,
    )

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
    # Kill-switch: when True, every access token carries a `jti` and the auth
    # path checks a Redis denylist (one cache GET per request). Lets logout /
    # compromise revoke an access token immediately instead of waiting out the
    # 15-minute lifetime. Off by default (keeps the zero-DB-query auth path).
    "ACCESS_TOKEN_DENYLIST_ENABLED": False,
    # ── Refresh Token ────────────────────────────────────
    "REFRESH_TOKEN_LIFETIME_DAYS": 30,
    "REFRESH_TOKEN_BYTES": 48,  # 384 bits of entropy
    "REFRESH_TOKEN_COOKIE_NAME": "refresh_token",
    "REFRESH_TOKEN_COOKIE_PATH": "/api/v1/auth/token/refresh/",
    "REFRESH_TOKEN_COOKIE_SECURE": True,  # Secure by default; set False only for local dev
    "REFRESH_TOKEN_COOKIE_SAMESITE": "Lax",
    "REFRESH_TOKEN_COOKIE_DOMAIN": None,  # None = host-only; set to ".example.com" for cross-subdomain
    # Prefix the refresh cookie name with `__Secure-` (2.0 default). The browser
    # then refuses to accept the cookie unless it was set with the Secure flag
    # over HTTPS — defence in depth against a downgraded/forged cookie. Only
    # applied when REFRESH_TOKEN_COOKIE_SECURE is True (the prefix is invalid on
    # a non-Secure cookie), so it is automatically inert in local HTTP dev.
    "USE_SECURE_COOKIE_PREFIX": True,
    # Grace window (seconds) for a legitimate refresh double-submit / retry. When
    # >0, reusing a just-rotated token whose replacement is still active and whose
    # fingerprint matches is treated as a fresh rotation of the current token,
    # instead of a replay (which revokes the whole family). 0 = strict replay
    # detection (default).
    "REFRESH_REUSE_GRACE_SECONDS": 0,
    # Cap on concurrent active refresh tokens (≈ sessions) per user. On a new
    # login beyond the cap, the oldest are revoked. None = unlimited.
    "MAX_ACTIVE_REFRESH_TOKENS_PER_USER": None,
    "TOKEN_MODEL": "tokenforge.RefreshToken",
    # ── Exchange Token ───────────────────────────────────
    "EXCHANGE_TOKEN_TTL_SECONDS": 60,
    "EXCHANGE_TOKEN_BYTES": 48,
    "EXCHANGE_TOKEN_MAX_ACTIVE": 5,
    # Allowlist of permitted exchange `target_origin` values (exact origins,
    # normalised). 2.0 is FAIL-CLOSED: when this is None/empty, every
    # create_exchange_token call is REFUSED. You must list your known subdomains
    # to use the exchange flow, so a token can never be minted for an attacker
    # origin. (1.x merely warned and allowed any origin.)
    "EXCHANGE_ALLOWED_ORIGINS": None,
    # Hard-fail exchange redemption when the redeeming request's fingerprint does
    # not match the one bound at creation (2.0 default). A leaked exchange token
    # (it rides in a URL) then can't be redeemed from another device.
    "EXCHANGE_FINGERPRINT_STRICT": True,
    # ── Security ─────────────────────────────────────────
    "FINGERPRINT_ENABLED": True,
    # Which request components form the device fingerprint. "ip" binds to the
    # client IP (changes on mobile WiFi↔LTE), "ua" binds to the User-Agent
    # (stable within a session). 2.0 defaults to ["ua"] because
    # FINGERPRINT_STRICT_REFRESH is now on by default: binding the IP would log
    # out web users on every legitimate network change (WiFi↔LTE, VPN, proxy
    # rotation). Add "ip" only if your clients have stable, trusted IPs.
    "FINGERPRINT_COMPONENTS": ["ua"],
    # Soft-warn on ACCESS TOKEN fingerprint drift (default). Set True only if
    # your deployment has stable, trusted client IPs — mobile/SPA users get
    # spurious logouts otherwise.
    "FINGERPRINT_STRICT_ACCESS_TOKEN": False,
    # Hard-fail REFRESH ROTATION on fingerprint drift (2.0 default: ON). Real
    # device-binding enforcement — a refresh from a different fingerprint is
    # rejected, not just logged. Paired with FINGERPRINT_COMPONENTS=["ua"] so a
    # network change is not treated as drift. Mobile is exempt: the mobile
    # refresh view sets strict_fingerprint=False and binds on the device session
    # instead. Set False to revert to monitor-only (1.x behaviour).
    "FINGERPRINT_STRICT_REFRESH": True,
    "REPLAY_DETECTION_ENABLED": True,
    "RISK_SCORE_THRESHOLD": 60,
    "BOT_SCORE_THRESHOLD": 90,
    "USER_CACHE_TTL": 300,  # 5 minutes
    # ── Callbacks (dotted import paths, optional) ────────
    "RISK_EVENT_HANDLER": None,
    "DEVICE_SESSION_VALIDATOR": None,  # fn(device_session) -> None or raises
    "DEVICE_SESSION_LOADER": None,  # fn(session_id, user) -> session or None
    "USER_SERIALIZER": None,
    # Optional override for fingerprint computation: any callable fn(request) -> str.
    # When None (default), the built-in tokenforge.security.RequestFingerprint is
    # used. A consumer may point this at their own callable (a function or a bound
    # class method both qualify).
    "FINGERPRINT_FUNCTION": None,
    # Resolve the tenant slug stamped into the access token's `tnt` claim.
    # fn(request, user) -> str | None. MUST be server-derived — never trust a
    # client-supplied value here. When None, `tnt` is empty (the safe default);
    # tokenforge no longer reads it from a client header.
    "TENANT_RESOLVER": None,
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
    "TENANT_RESOLVER",
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

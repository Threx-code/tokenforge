import warnings

from django.apps import AppConfig
from django.core.exceptions import ImproperlyConfigured


class TokenForgeConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "tokenforge"
    verbose_name = "TokenForge Authentication"

    def ready(self) -> None:
        import tokenforge.signals  # noqa: F401 — register signal definitions

        self._warn_unsafe_cookie_config()
        self._warn_concurrency_db()

    @staticmethod
    def _warn_unsafe_cookie_config() -> None:
        """Guard cookie configurations that widen the refresh-token exposure
        (SD-1, SD-5). A domain-wide OR path='/' cookie is warned (some
        deployments deliberately accept it); the combination of BOTH — the
        broadest possible exposure — is a hard error in 2.0."""
        from tokenforge.settings import tokenforge_settings

        domain = tokenforge_settings.REFRESH_TOKEN_COOKIE_DOMAIN
        path = tokenforge_settings.REFRESH_TOKEN_COOKIE_PATH

        if domain and path == "/":
            raise ImproperlyConfigured(
                "TOKENFORGE refresh cookie is both domain-wide "
                f"(REFRESH_TOKEN_COOKIE_DOMAIN={domain!r}) AND path='/': the refresh token "
                "would be sent to every endpoint on every subdomain — the broadest possible "
                "exposure. Narrow at least one (host-only domain=None, or scope the path to "
                "the refresh endpoint)."
            )
        if domain:
            warnings.warn(
                f"TOKENFORGE['REFRESH_TOKEN_COOKIE_DOMAIN']={domain!r} sends the refresh "
                "cookie to EVERY subdomain — including a hostile or taken-over one, which "
                "can capture the raw token server-side. Prefer host-only cookies "
                "(domain=None) + the exchange flow for cross-subdomain handoff.",
                stacklevel=2,
            )
        if path == "/":
            warnings.warn(
                "TOKENFORGE['REFRESH_TOKEN_COOKIE_PATH']='/' sends the refresh cookie to "
                "every endpoint on the host. Scope it to the refresh endpoint path.",
                stacklevel=2,
            )

    @staticmethod
    def _warn_concurrency_db() -> None:
        """Refresh rotation relies on SELECT FOR UPDATE (with `of=`) to serialise
        concurrent rotations and make replay detection race-free. That guarantee
        only holds on PostgreSQL (M4); warn otherwise."""
        from django.db import connection

        from tokenforge.settings import tokenforge_settings

        if tokenforge_settings.REPLAY_DETECTION_ENABLED and connection.vendor != "postgresql":
            warnings.warn(
                f"tokenforge: database vendor is {connection.vendor!r}, not 'postgresql'. "
                "Refresh-token rotation's SELECT FOR UPDATE concurrency protection is reduced "
                "or absent, so concurrent rotations / replay detection may race. PostgreSQL is "
                "recommended for the concurrency guarantee.",
                stacklevel=2,
            )

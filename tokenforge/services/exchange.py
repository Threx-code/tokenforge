"""
Exchange Token Service — one-time cross-subdomain auth handoff via Redis.

Flow:
  1. Authenticated user on base domain calls ExchangeTokenService.create()
  2. Server stores {user_id, session_id, fingerprint, target_origin} in Redis (60s TTL)
  3. User is redirected to target subdomain with #token=<exchange_token> in URL
  4. Subdomain calls ExchangeTokenService.redeem() → auth context → issues new tokens
  5. Redis key is deleted on redeem (single-use)

Security:
  - 60-second TTL prevents stale tokens from being useful
  - Single-use: atomic claim, deleted from Redis on redemption
  - Origin binding: target_origin must be allowlisted and match the redeemer
  - Device-fingerprint binding on redemption (EXCHANGE_FINGERPRINT_STRICT)
  - High entropy: 48 bytes (384 bits) of cryptographic randomness
  - Rate-limited at the view layer
"""

import hmac
import logging
from urllib.parse import urlparse

from tokenforge.tokens import OneTimeStore

logger = logging.getLogger("tokenforge")


class ExchangeTokenService:
    """Create / redeem one-time cross-subdomain exchange tokens.

    Stateless (all state lives in the cache via the OneTimeStore), so the public
    surface is classmethods.
    """

    # Stored under the "exchange" namespace → cache key "tokenforge:exchange:<token>".
    NAMESPACE = "exchange"
    _store = OneTimeStore(NAMESPACE)

    # ── helpers ──────────────────────────────────────────
    @staticmethod
    def _normalize_origin(origin: str) -> str:
        """Normalize an origin URL for comparison: strip trailing slashes,
        lowercase scheme + host, keep port."""
        origin = origin.strip().rstrip("/").lower()
        parsed = urlparse(origin)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        return origin

    @classmethod
    def _check_target_origin_allowed(cls, normalized_origin: str) -> None:
        """Enforce EXCHANGE_ALLOWED_ORIGINS (2.0: fail-closed). Raises ValueError
        if the (normalised) target origin is not on the allowlist. When the
        allowlist is unset or empty, EVERY origin is refused — you must list your
        known subdomains to mint an exchange token, so a token can never be created
        for an attacker origin.
        """
        from tokenforge.settings import tokenforge_settings

        allowed = tokenforge_settings.EXCHANGE_ALLOWED_ORIGINS
        if not allowed:
            raise ValueError(
                "TOKENFORGE['EXCHANGE_ALLOWED_ORIGINS'] is not set — exchange token creation "
                "is refused (fail-closed). Set it to your known subdomains to use the exchange flow."
            )
        allowed_set = {cls._normalize_origin(o) for o in allowed}
        if normalized_origin not in allowed_set:
            raise ValueError("Exchange target origin is not allowed")

    # ── public API ───────────────────────────────────────
    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        device_session_id: str,
        fingerprint: str = "",
        target_origin: str,
    ) -> str:
        """Create a one-time exchange token and store it.

        Returns the raw exchange token (delivered to the target subdomain, ideally
        in the URL fragment — see the SD-4 README note). Raises ValueError if the
        target origin is not allowlisted.
        """
        from tokenforge.settings import tokenforge_settings

        ttl = int(tokenforge_settings.EXCHANGE_TOKEN_TTL_SECONDS)
        normalized_origin = cls._normalize_origin(target_origin)
        cls._check_target_origin_allowed(normalized_origin)

        payload = {
            "sub": str(user_id),
            "sid": str(device_session_id),
            "fp": fingerprint,
            "target_origin": normalized_origin,
        }

        token = cls._store.create(
            payload, ttl=ttl, nbytes=int(tokenforge_settings.EXCHANGE_TOKEN_BYTES)
        )
        # Track for the per-user active cap. Pruned-on-read, so an unredeemed token
        # that simply expires stops counting on its own (no counter drift).
        cls._store.track(str(user_id), token, ttl=ttl)

        logger.info(
            "Exchange token created: user=%s, target=%s, ttl=%ds", user_id, target_origin, ttl
        )
        return token

    @classmethod
    def redeem(
        cls,
        *,
        token: str,
        request_origin: str = "",
        request_fingerprint: str = "",
    ) -> dict[str, str]:
        """Redeem a one-time exchange token.

        Atomically claims the token, checks origin + fingerprint binding, and
        returns the auth context {sub, sid, fp, target_origin}. The active count
        is released before validation so a rejected redeem doesn't leak the slot.

        Raises ValueError on any validation failure.
        """
        if not token:
            raise ValueError("Exchange token is required")

        # Atomic single-use claim. Fixes the get-then-delete race where two
        # concurrent redemptions could both read the payload before either deleted
        # it; claim() guarantees exactly one redemption wins.
        payload = cls._store.claim(token)
        if payload is None:
            raise ValueError("Exchange token is invalid or expired")

        # The token has been consumed — release the user's active slot now, before
        # validation, so the count is freed even if a later check rejects it.
        user_id = payload.get("sub", "")
        if user_id:
            cls._store.untrack(str(user_id), token)

        # Validate required fields
        for field in ("sub", "sid"):
            if not payload.get(field):
                raise ValueError(f"Exchange token missing required field: {field}")

        # Origin binding check — if the token has a target_origin, enforce it.
        # Missing Origin header is treated as a mismatch when binding is set.
        target_origin = payload.get("target_origin", "")
        if target_origin:
            if not request_origin:
                logger.warning(
                    "Exchange token redeemed without Origin header: user=%s, expected=%s",
                    user_id,
                    target_origin,
                )
                raise ValueError("Exchange token origin verification failed")

            if cls._normalize_origin(request_origin) != target_origin:
                logger.warning(
                    "Exchange token origin mismatch: expected=%s, got=%s, user=%s",
                    target_origin,
                    cls._normalize_origin(request_origin),
                    user_id,
                )
                raise ValueError("Exchange token origin mismatch")

        # Device-fingerprint binding. The stored fp is the 16-char prefix bound at
        # creation; compare it to the redeeming request's fingerprint so a leaked
        # token (it rides in a URL) can't be redeemed from another device.
        # Hard-fails only when EXCHANGE_FINGERPRINT_STRICT is on (2.0 default).
        stored_fp = str(payload.get("fp", ""))
        if stored_fp and request_fingerprint:
            from tokenforge.settings import tokenforge_settings

            if not hmac.compare_digest(stored_fp, request_fingerprint[:16]):
                logger.warning("Exchange token fingerprint drift: user=%s", user_id)
                if tokenforge_settings.EXCHANGE_FINGERPRINT_STRICT:
                    raise ValueError("Exchange token fingerprint mismatch")

        logger.info("Exchange token redeemed: user=%s, origin=%s", user_id, request_origin)
        return dict(payload)

    @classmethod
    def count_active(cls, user_id: str) -> int:
        """Count a user's outstanding (non-expired) exchange tokens.

        Backed by the OneTimeStore's pruned-on-read active set, so a token that
        expired without being redeemed no longer counts — unlike the old incr/decr
        integer counter, which drifted upward on every unredeemed expiry.
        """
        return cls._store.count_active(str(user_id))

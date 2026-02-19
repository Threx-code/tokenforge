"""
Exchange Token Service — one-time cross-subdomain auth handoff via Redis.

Flow:
  1. Authenticated user on base domain calls create_exchange_token()
  2. Server stores {user_id, session_id, fingerprint, target_origin} in Redis (60s TTL)
  3. User is redirected to target subdomain with ?token=<exchange_token> in URL
  4. Subdomain calls redeem_exchange_token() → gets auth context → issues new tokens
  5. Redis key is deleted on redeem (single-use)

Security:
  - 60-second TTL prevents stale tokens from being useful
  - Single-use: deleted from Redis on redemption
  - Origin binding: target_origin must match the requesting origin
  - High entropy: 48 bytes (384 bits) of cryptographic randomness
  - Rate-limited at the view layer
"""

import json
import logging
import secrets
from urllib.parse import urlparse

from django.core.cache import cache

logger = logging.getLogger("tokenforge")

_CACHE_KEY_PREFIX = "tokenforge:exchange:"


def _get_ttl() -> int:
    from tokenforge.settings import tokenforge_settings

    return int(tokenforge_settings.EXCHANGE_TOKEN_TTL_SECONDS)


def _get_bytes() -> int:
    from tokenforge.settings import tokenforge_settings

    return int(tokenforge_settings.EXCHANGE_TOKEN_BYTES)


def _get_max_active() -> int:
    from tokenforge.settings import tokenforge_settings

    return int(tokenforge_settings.EXCHANGE_TOKEN_MAX_ACTIVE)


def _cache_key(token: str) -> str:
    return f"{_CACHE_KEY_PREFIX}{token}"


def _normalize_origin(origin: str) -> str:
    """
    Normalize an origin URL for comparison.

    Strips trailing slashes and lowercases the scheme + host.
    Keeps port if present.
    """
    origin = origin.strip().rstrip("/").lower()
    parsed = urlparse(origin)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return origin


# ─────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────


def create_exchange_token(
    *,
    user_id: str,
    device_session_id: str,
    fingerprint: str = "",
    target_origin: str,
) -> str:
    """
    Create a one-time exchange token and store in Redis.

    Args:
        user_id: UUID of the authenticated user.
        device_session_id: UUID of the current device session.
        fingerprint: SHA-256(IP|UA) for binding verification.
        target_origin: The origin the token is valid for.

    Returns:
        The raw exchange token string (to be passed in URL query param).
    """
    token = secrets.token_urlsafe(_get_bytes())
    ttl = _get_ttl()

    payload = {
        "sub": str(user_id),
        "sid": str(device_session_id),
        "fp": fingerprint,
        "target_origin": _normalize_origin(target_origin),
    }

    cache.set(_cache_key(token), json.dumps(payload), timeout=ttl)

    logger.info(
        "Exchange token created: user=%s, target=%s, ttl=%ds",
        user_id,
        target_origin,
        ttl,
    )

    return token


def redeem_exchange_token(
    *,
    token: str,
    request_origin: str = "",
) -> dict[str, str]:
    """
    Redeem a one-time exchange token.

    Validates the token exists in Redis, checks origin binding,
    deletes the token (single-use), and returns the auth context.

    The active-token counter is always decremented when a token is consumed
    (deleted from Redis), regardless of whether subsequent validation passes.
    This prevents counter leaks when tokens are rejected after deletion.

    Args:
        token: The raw exchange token from the URL query param.
        request_origin: The Origin or Referer header from the request.

    Returns:
        Dict with keys: sub, sid, fp, target_origin

    Raises:
        ValueError: On any validation failure.
    """
    if not token:
        raise ValueError("Exchange token is required")

    key = _cache_key(token)
    raw_payload = cache.get(key)

    if raw_payload is None:
        raise ValueError("Exchange token is invalid or expired")

    # Delete immediately (single-use) — even if validation below fails,
    # we don't want the token to be reusable.
    cache.delete(key)

    try:
        payload = json.loads(raw_payload)
    except (json.JSONDecodeError, TypeError) as e:
        logger.error("Corrupt exchange token payload for token (deleted)")
        raise ValueError("Exchange token payload corrupted") from e

    # Always decrement the counter now that the token has been consumed.
    # This runs before validation so counter is decremented even on failure.
    user_id = payload.get("sub", "")
    if user_id:
        decrement_exchange_counter(user_id)

    # Validate required fields
    for field in ("sub", "sid"):
        if not payload.get(field):
            raise ValueError(f"Exchange token missing required field: {field}")

    # Origin binding check — if the token has a target_origin, enforce it.
    # Missing Origin/Referer header is treated as a mismatch when binding is set.
    target_origin = payload.get("target_origin", "")
    if target_origin:
        if not request_origin:
            logger.warning(
                "Exchange token redeemed without Origin header: user=%s, expected=%s",
                user_id,
                target_origin,
            )
            raise ValueError("Exchange token origin verification failed")

        normalized_request = _normalize_origin(request_origin)
        normalized_target = target_origin
        if normalized_request != normalized_target:
            logger.warning(
                "Exchange token origin mismatch: expected=%s, got=%s, user=%s",
                normalized_target,
                normalized_request,
                user_id,
            )
            raise ValueError("Exchange token origin mismatch")

    logger.info(
        "Exchange token redeemed: user=%s, origin=%s",
        user_id,
        request_origin,
    )

    return dict(payload)


def count_active_exchange_tokens(user_id: str) -> int:
    """
    Count active exchange tokens for a user.

    Uses a secondary counter key in Redis to track outstanding tokens.
    """
    counter_key = f"tokenforge:exchange_count:{user_id}"
    count = cache.get(counter_key)
    return int(count) if count else 0


def increment_exchange_counter(user_id: str) -> None:
    """Increment the exchange token counter for a user."""
    counter_key = f"tokenforge:exchange_count:{user_id}"
    ttl = _get_ttl() * 2  # Counter lives slightly longer than any single token
    # Use cache.add (atomic create-if-not-exists) to avoid race conditions
    # between cache.incr failing and cache.set overwriting a concurrent write.
    if cache.add(counter_key, 0, timeout=ttl):
        pass  # Key created with value 0, incr below will make it 1
    try:
        cache.incr(counter_key)
    except ValueError:
        # Fallback: key may have expired between add and incr
        cache.set(counter_key, 1, timeout=ttl)


def decrement_exchange_counter(user_id: str) -> None:
    """Decrement the exchange token counter for a user."""
    counter_key = f"tokenforge:exchange_count:{user_id}"
    try:
        val = cache.decr(counter_key)
        if val <= 0:
            cache.delete(counter_key)
    except ValueError:
        pass

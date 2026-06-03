"""
Access-token denylist — the kill-switch (M2).

Stateless access tokens normally can't be revoked before they expire. When
``ACCESS_TOKEN_DENYLIST_ENABLED`` is on, the auth path checks this denylist for
the token's ``jti`` (one cache GET per request), and logout / compromise adds
the ``jti`` with a TTL equal to the token's *remaining* lifetime. The entry
therefore self-expires exactly when the token would have anyway — the denylist
never grows unbounded.

No-op unless enabled. The check lives on the authentication path, so decoding a
token with ``AccessToken.verify`` for display does not incur the cache hit.
"""

import logging
import time

from django.core.cache import cache

logger = logging.getLogger("tokenforge")


class AccessTokenDenylist:
    """Cache-backed denylist of revoked access-token ``jti`` values (kill-switch)."""

    _PREFIX = "tokenforge:denylist:"

    @classmethod
    def _key(cls, jti: str) -> str:
        return f"{cls._PREFIX}{jti}"

    @classmethod
    def add(cls, jti: str, *, exp: int | None = None, ttl: int | None = None) -> None:
        """Revoke an access token by its ``jti`` until it would have expired.

        Provide either ``ttl`` (remaining seconds) or ``exp`` (unix expiry, from
        which the TTL is derived). No-op if ``jti`` is empty or the token has
        already expired (ttl <= 0).
        """
        if not jti:
            return
        if ttl is None and exp is not None:
            try:
                ttl = int(exp) - int(time.time())
            except (TypeError, ValueError):
                return
        if not ttl or ttl <= 0:
            return
        cache.set(cls._key(jti), 1, timeout=ttl)
        logger.info("Access token denylisted: jti=%s ttl=%ds", jti, ttl)

    @classmethod
    def contains(cls, jti: str) -> bool:
        """True if this ``jti`` has been revoked and not yet expired."""
        if not jti:
            return False
        return cache.get(cls._key(jti)) is not None

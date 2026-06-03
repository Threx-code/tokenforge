"""
One-time token store — short-TTL, single-use values in the cache.

Exchange tokens build on this, and consuming apps should too (e.g. a step-up /
re-auth grant) so the single-use guarantee is implemented and audited in exactly
one place.

Why this exists
---------------
The obvious implementation — ``cache.get(key)`` then ``cache.delete(key)`` — is
**not** single-use under concurrency: two parallel redemptions can both read a
non-``None`` value before either deletes it, so a "single-use" token gets
redeemed twice.

``claim()`` here is atomic. The trick is to arbitrate on ``cache.delete()``'s
return value rather than on ``cache.get()``: ``delete`` returns ``True`` only for
the caller that actually removed the key (Django ≥ 3.1). Redis ``DEL`` is a
single atomic command (one racer gets ``1``, the rest get ``0``), and
``LocMemCache.delete`` is lock-guarded, so across every supported backend exactly
one concurrent claimer wins.

A store is scoped to a ``namespace`` (its instance state), so exchange tokens and
step-up grants live under separate key spaces without repeating the namespace at
every call: ``OneTimeStore("exchange").claim(token)``.
"""

import json
import logging
import secrets
import time
from typing import Any

from django.core.cache import cache

logger = logging.getLogger("tokenforge")

DEFAULT_NAMESPACE = "onetime"


class OneTimeStore:
    """Atomic single-use token store + per-owner active cap, scoped to a namespace."""

    def __init__(self, namespace: str = DEFAULT_NAMESPACE) -> None:
        self.namespace = namespace

    # ── keys ─────────────────────────────────────────────
    def _key(self, token: str) -> str:
        return f"tokenforge:{self.namespace}:{token}"

    def _active_key(self, owner: str) -> str:
        return f"tokenforge:{self.namespace}_active:{owner}"

    # ── single-use tokens ────────────────────────────────
    def create(self, payload: dict[str, Any], *, ttl: int, nbytes: int = 48) -> str:
        """Store ``payload`` under a fresh single-use token and return the token.

        ``ttl`` is in seconds; ``nbytes`` controls token entropy (48 → 384 bits).
        """
        token = secrets.token_urlsafe(nbytes)
        cache.set(self._key(token), json.dumps(payload), timeout=ttl)
        return token

    def claim(self, token: str) -> dict[str, Any] | None:
        """Atomically consume a one-time token.

        Returns the stored payload, or ``None`` if the token is unknown, expired,
        or already claimed. Under concurrent claims of the same token, exactly one
        call returns the payload and the rest return ``None``.
        """
        if not token:
            return None

        key = self._key(token)
        raw = cache.get(key)
        if raw is None:
            return None

        # Arbiter: only the caller whose delete actually removed the key may use
        # the payload. Everyone else lost the race ("already claimed").
        if not cache.delete(key):
            return None

        try:
            result: dict[str, Any] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            logger.error(
                "tokenforge.tokens.onetime: corrupt payload for a claimed token (namespace=%s)",
                self.namespace,
            )
            return None
        return result

    # ── per-owner active count (pruned-on-read) ──────────
    #
    # A soft cap on how many one-time tokens an owner (e.g. a user) may have
    # outstanding. The naive incr/decr integer counter *drifts*: a token that
    # expires via TTL without being claimed never decrements, so the counter
    # over-counts and eventually locks the owner out of creating new tokens.
    #
    # Here each owner has a single cache entry mapping ``token -> expiry_unix``.
    # Every read/write prunes members whose expiry has passed, so an unclaimed
    # token that simply timed out stops counting on its own. Best-effort
    # *availability* cap, not a security boundary — the single-use guarantee lives
    # in ``claim()``. Portable across every cache backend (no Redis-only ZSETs).

    def _load_active(self, key: str, now: int) -> dict[str, int]:
        raw = cache.get(key)
        if not raw:
            return {}
        try:
            entries: dict[str, int] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}
        return {tok: exp for tok, exp in entries.items() if exp > now}

    def track(self, owner: str, token: str, *, ttl: int) -> None:
        """Record ``token`` as an active member of ``owner``'s set, expiring in
        ``ttl`` seconds. Prunes already-expired members on write."""
        key = self._active_key(owner)
        now = int(time.time())
        entries = self._load_active(key, now)
        entries[token] = now + ttl
        bucket_ttl = max(entries.values()) - now + 60
        cache.set(key, json.dumps(entries), timeout=bucket_ttl)

    def untrack(self, owner: str, token: str) -> None:
        """Remove ``token`` from ``owner``'s active set (called when it is claimed)."""
        key = self._active_key(owner)
        now = int(time.time())
        entries = self._load_active(key, now)
        entries.pop(token, None)
        if entries:
            cache.set(key, json.dumps(entries), timeout=max(entries.values()) - now + 60)
        else:
            cache.delete(key)

    def count_active(self, owner: str) -> int:
        """Return the number of non-expired active tokens for ``owner``."""
        return len(self._load_active(self._active_key(owner), int(time.time())))

"""
Bearer Token Authentication — stateless DRF authentication class.

Flow:
  1. Client sends: Authorization: Bearer <access_token>
  2. Extract token from header
  3. Verify HMAC signature + expiry (no DB hit)
  4. Load user from cache/DB using "sub" claim
  5. Set request.user and request.auth (token payload dict)

Performance:
  - Normal requests: 0 DB queries (token is self-contained)
  - First request per user: 1 DB query to load user (then cached)
"""

import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.http import HttpRequest
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .tokens import verify_access_token

logger = logging.getLogger("tokenforge")

User = get_user_model()

_USER_CACHE_PREFIX = "tokenforge:user:"


def invalidate_user_cache(user_id: str) -> None:
    """
    Remove a user from the tokenforge auth cache.

    Call this when a user is deactivated, deleted, or their permissions change,
    so the next request triggers a fresh DB lookup.
    """
    cache.delete(f"{_USER_CACHE_PREFIX}{user_id}")


class BearerTokenAuthentication(BaseAuthentication):
    """
    DRF authentication class for stateless Bearer tokens.

    Usage:
        REST_FRAMEWORK = {
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "tokenforge.authentication.BearerTokenAuthentication",
            ],
        }
    """

    keyword = "Bearer"

    def authenticate(self, request: HttpRequest) -> tuple[Any, dict[str, Any]] | None:
        """
        Authenticate the request and return (user, auth_context) or None.

        Returns None if no Authorization header is present.
        Raises AuthenticationFailed if a Bearer token is present but invalid.
        """
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")

        if not auth_header:
            return None

        parts = auth_header.split(" ", 1)

        if len(parts) != 2 or parts[0] != self.keyword:
            return None

        token_string = parts[1].strip()

        if not token_string:
            raise AuthenticationFailed("Authentication required")

        # Verify token (stateless HMAC check)
        try:
            request_fingerprint = self._get_request_fingerprint(request)
            payload = verify_access_token(
                token_string,
                request_fingerprint=request_fingerprint,
            )
        except ValueError as e:
            logger.warning("Bearer token verification failed: %s", str(e))
            raise AuthenticationFailed("Authentication failed") from e

        # Load user
        user_id = payload.get("sub")
        if not user_id:
            logger.warning("Bearer token missing 'sub' claim")
            raise AuthenticationFailed("Authentication failed")

        user = self._get_user(str(user_id))
        if user is None:
            logger.warning("Bearer token references non-existent user: %s", user_id)
            raise AuthenticationFailed("Authentication failed")

        if not user.is_active:
            logger.warning("Bearer token for disabled user: %s", user_id)
            raise AuthenticationFailed("Authentication failed")

        # Build auth context
        auth_context = {
            "sub": payload["sub"],
            "sid": payload.get("sid", ""),
            "fp": payload.get("fp", ""),
            "tnt": payload.get("tnt", ""),
            "iat": payload.get("iat"),
            "exp": payload.get("exp"),
            "v": payload.get("v", ""),
            "token_type": "bearer",
        }

        return user, auth_context

    def authenticate_header(self, request: HttpRequest) -> str:
        return f'{self.keyword} realm="api"'

    def _get_user(self, user_id: str) -> Any | None:
        """Load user by UUID, with caching.

        Caches only active users. If the cached user has been deactivated
        since caching, we detect the stale flag and re-fetch from DB.
        """
        from tokenforge.settings import tokenforge_settings

        cache_ttl = tokenforge_settings.USER_CACHE_TTL

        cache_key = f"{_USER_CACHE_PREFIX}{user_id}"
        user = cache.get(cache_key)

        if user is not None:
            # Guard against stale cache: if user was deactivated since caching,
            # evict from cache and re-fetch from DB to confirm.
            if not user.is_active:
                cache.delete(cache_key)
                return None
            return user

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

        # Only cache active users
        if user.is_active:
            cache.set(cache_key, user, timeout=cache_ttl)
        return user

    @staticmethod
    def _get_request_fingerprint(request: HttpRequest) -> str | None:
        """Compute fingerprint for the current request via configurable function."""
        from tokenforge.settings import tokenforge_settings

        if not tokenforge_settings.FINGERPRINT_ENABLED:
            return None

        try:
            fingerprint_fn = tokenforge_settings.FINGERPRINT_FUNCTION
            return str(fingerprint_fn(request))
        except Exception:
            return None

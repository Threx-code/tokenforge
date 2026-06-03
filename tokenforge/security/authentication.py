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

from tokenforge.security.fingerprinting import RequestFingerprint
from tokenforge.tokens import AccessToken, AccessTokenDenylist

logger = logging.getLogger("tokenforge")

User = get_user_model()


class UserCache:
    """Caches authenticated ``User`` objects so the auth path stays DB-free.

    Caches only active users; a cached user that has since been deactivated is
    detected (stale ``is_active``) and re-fetched.
    """

    _PREFIX = "tokenforge:user:"

    @classmethod
    def _key(cls, user_id: str) -> str:
        return f"{cls._PREFIX}{user_id}"

    @classmethod
    def invalidate(cls, user_id: str) -> None:
        """Remove a user from the auth cache.

        Call this when a user is deactivated, deleted, or their permissions
        change, so the next request triggers a fresh DB lookup.
        """
        cache.delete(cls._key(user_id))

    @classmethod
    def get(cls, user_id: str) -> Any | None:
        """Load a user by id, with caching. Returns None if missing/inactive."""
        from tokenforge.settings import tokenforge_settings

        cache_key = cls._key(user_id)
        user = cache.get(cache_key)

        if user is not None:
            # Guard against stale cache: if the user was deactivated since
            # caching, evict and re-fetch from DB to confirm.
            if not user.is_active:
                cache.delete(cache_key)
                return None
            return user

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

        if user.is_active:  # only cache active users
            cache.set(cache_key, user, timeout=tokenforge_settings.USER_CACHE_TTL)
        return user


class BearerTokenAuthentication(BaseAuthentication):
    """
    DRF authentication class for stateless Bearer tokens.

    Usage:
        REST_FRAMEWORK = {
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "tokenforge.security.authentication.BearerTokenAuthentication",
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
            payload = AccessToken.verify(
                token_string,
                request_fingerprint=request_fingerprint,
            )
        except ValueError as e:
            logger.warning("Bearer token verification failed: %s", str(e))
            raise AuthenticationFailed("Authentication failed") from e
        except Exception as e:
            # Defense-in-depth: a malformed token must never crash the request
            # with a 500. Any unexpected error during verification → auth failure.
            logger.warning("Bearer token verification error: %s", str(e))
            raise AuthenticationFailed("Authentication failed") from e

        # Denylist (kill-switch) — only when enabled, one cache GET. Lets logout /
        # compromise revoke this access token before its natural expiry.
        from tokenforge.settings import tokenforge_settings

        if tokenforge_settings.ACCESS_TOKEN_DENYLIST_ENABLED and AccessTokenDenylist.contains(
            str(payload.get("jti", ""))
        ):
            logger.warning("Bearer token is denylisted: jti=%s", payload.get("jti"))
            raise AuthenticationFailed("Authentication failed")

        # Load user
        user_id = payload.get("sub")
        if not user_id:
            logger.warning("Bearer token missing 'sub' claim")
            raise AuthenticationFailed("Authentication failed")

        user = UserCache.get(str(user_id))
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
            "jti": payload.get("jti", ""),
            "iat": payload.get("iat"),
            "exp": payload.get("exp"),
            "v": payload.get("v", ""),
            "token_type": "bearer",
        }

        return user, auth_context

    def authenticate_header(self, request: HttpRequest) -> str:
        return f'{self.keyword} realm="api"'

    @staticmethod
    def _get_request_fingerprint(request: HttpRequest) -> str | None:
        """Compute the fingerprint for the current request.

        Uses the optional FINGERPRINT_FUNCTION callable hook when configured,
        otherwise the built-in RequestFingerprint.
        """
        from tokenforge.settings import tokenforge_settings

        if not tokenforge_settings.FINGERPRINT_ENABLED:
            return None

        try:
            fingerprint_fn = tokenforge_settings.FINGERPRINT_FUNCTION
            if fingerprint_fn:
                return str(fingerprint_fn(request))
            return RequestFingerprint(request).compute()
        except Exception:
            return None

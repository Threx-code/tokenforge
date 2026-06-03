"""
Tests for tokenforge.security.authentication — BearerTokenAuthentication.
"""

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import RequestFactory
from rest_framework.exceptions import AuthenticationFailed

from tokenforge.security.authentication import BearerTokenAuthentication, UserCache
from tokenforge.tokens import AccessToken

User = get_user_model()
pytestmark = pytest.mark.django_db

factory = RequestFactory()


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture()
def user(db):
    return User.objects.create_user(username="auth_user", password="pass")


@pytest.fixture()
def inactive_user(db):
    return User.objects.create_user(username="inactive_user", password="pass", is_active=False)


def make_token(user_id, **kwargs):
    token, _ = AccessToken.create(user_id=str(user_id), **kwargs)
    return token


def make_request(token=None, user_id=None, **token_kwargs):
    """Build a GET request with an Authorization: Bearer header."""
    request = factory.get("/")
    request.META["REMOTE_ADDR"] = "1.2.3.4"
    request.META["HTTP_USER_AGENT"] = "TestAgent/1.0"
    if token is None and user_id is not None:
        token = make_token(user_id, **token_kwargs)
    if token is not None:
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return request


# ── authenticate — happy path ─────────────────────────────────────────────────


class TestBearerAuthHappyPath:
    def test_returns_tuple_of_user_and_context(self, user):
        request = make_request(user_id=user.id)
        auth = BearerTokenAuthentication()
        result = auth.authenticate(request)
        assert result is not None
        returned_user, context = result
        assert returned_user.pk == user.pk
        assert isinstance(context, dict)

    def test_auth_context_contains_sub(self, user):
        request = make_request(user_id=user.id)
        _, context = BearerTokenAuthentication().authenticate(request)
        assert context["sub"] == str(user.id)

    def test_auth_context_contains_token_type(self, user):
        request = make_request(user_id=user.id)
        _, context = BearerTokenAuthentication().authenticate(request)
        assert context["token_type"] == "bearer"

    def test_auth_context_contains_exp_and_iat(self, user):
        request = make_request(user_id=user.id)
        _, context = BearerTokenAuthentication().authenticate(request)
        assert "exp" in context
        assert "iat" in context

    def test_sid_in_context(self, user):
        request = make_request(user_id=user.id, device_session_id="sess-abc")
        _, context = BearerTokenAuthentication().authenticate(request)
        assert context["sid"] == "sess-abc"

    def test_tnt_in_context(self, user):
        request = make_request(user_id=user.id, tenant_slug="acme")
        _, context = BearerTokenAuthentication().authenticate(request)
        assert context["tnt"] == "acme"


# ── authenticate — returns None (unauthenticated, not an error) ───────────────


class TestBearerAuthReturnsNone:
    def test_no_auth_header_returns_none(self):
        request = factory.get("/")
        result = BearerTokenAuthentication().authenticate(request)
        assert result is None

    def test_empty_auth_header_returns_none(self):
        request = factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = ""
        result = BearerTokenAuthentication().authenticate(request)
        assert result is None

    def test_non_bearer_scheme_returns_none(self):
        request = factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = "Basic dXNlcjpwYXNz"
        result = BearerTokenAuthentication().authenticate(request)
        assert result is None

    def test_wrong_keyword_case_returns_none(self):
        request = factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = "bearer sometoken"
        result = BearerTokenAuthentication().authenticate(request)
        assert result is None


# ── authenticate — raises AuthenticationFailed ────────────────────────────────


class TestBearerAuthFailed:
    def test_bearer_with_empty_token_raises(self):
        request = factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = "Bearer "
        with pytest.raises(AuthenticationFailed):
            BearerTokenAuthentication().authenticate(request)

    def test_tampered_token_raises(self, user):
        token = make_token(user.id)
        parts = token.split(".")
        bad_token = parts[0] + ".invalidsignatureXXX"
        request = factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {bad_token}"
        with pytest.raises(AuthenticationFailed):
            BearerTokenAuthentication().authenticate(request)

    def test_nonexistent_user_raises(self, db):
        # Use a user ID that is extremely unlikely to exist (99999999)
        token = make_token(99999999)
        request = factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        with pytest.raises(AuthenticationFailed):
            BearerTokenAuthentication().authenticate(request)

    def test_inactive_user_raises(self, inactive_user):
        token = make_token(inactive_user.id)
        request = factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        with pytest.raises(AuthenticationFailed):
            BearerTokenAuthentication().authenticate(request)

    def test_malformed_token_raises(self):
        request = factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = "Bearer notavalidtoken"
        with pytest.raises(AuthenticationFailed):
            BearerTokenAuthentication().authenticate(request)


# ── authenticate_header ───────────────────────────────────────────────────────


class TestAuthenticateHeader:
    def test_returns_bearer_realm(self):
        request = factory.get("/")
        header = BearerTokenAuthentication().authenticate_header(request)
        assert "Bearer" in header
        assert "realm" in header


# ── UserCache.invalidate ─────────────────────────────────────────────────────


class TestInvalidateUserCache:
    def test_invalidate_does_not_raise(self, user):
        # Populate the cache first by authenticating
        request = make_request(user_id=user.id)
        BearerTokenAuthentication().authenticate(request)
        # Then invalidate — must not raise
        UserCache.invalidate(str(user.id))

    def test_after_invalidation_user_reloaded_from_db(self, user):
        auth = BearerTokenAuthentication()
        # Authenticate once to cache
        request = make_request(user_id=user.id)
        auth.authenticate(request)
        # Invalidate
        UserCache.invalidate(str(user.id))
        # Authenticate again — should re-fetch from DB and succeed
        result = auth.authenticate(make_request(user_id=user.id))
        assert result is not None
        assert result[0].pk == user.pk

    def test_invalidate_nonexistent_key_does_not_raise(self):
        UserCache.invalidate("00000000-0000-0000-0000-000000000001")


# ── user caching behaviour ────────────────────────────────────────────────────


class TestUserCaching:
    def test_stale_cache_evicted_when_user_deactivated_and_cache_invalidated(self, user):
        """
        When a user is deactivated and the cache is explicitly invalidated
        (e.g. via a signal or admin action), subsequent requests must fail.
        """
        auth = BearerTokenAuthentication()
        token = make_token(user.id)

        # Temporarily enable caching
        from django.conf import settings as django_settings

        from tokenforge.settings import reload_settings

        original = django_settings.TOKENFORGE.copy()
        django_settings.TOKENFORGE = {**original, "USER_CACHE_TTL": 300}
        reload_settings()

        try:
            # First auth succeeds and populates the cache
            request = factory.get("/")
            request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
            result = auth.authenticate(request)
            assert result is not None

            # Deactivate user in DB and invalidate the cache
            user.is_active = False
            user.save()
            UserCache.invalidate(str(user.id))

            # Next request should re-fetch from DB and reject the inactive user
            request2 = factory.get("/")
            request2.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
            with pytest.raises(AuthenticationFailed):
                auth.authenticate(request2)
        finally:
            django_settings.TOKENFORGE = original
            reload_settings()

    def test_cached_user_with_is_active_false_rejected(self, user):
        """
        If the in-memory cached user object has is_active=False (e.g. set directly
        on the instance), the auth backend must evict and reject.
        """
        auth = BearerTokenAuthentication()
        token = make_token(user.id)

        from django.conf import settings as django_settings

        from tokenforge.settings import reload_settings

        original = django_settings.TOKENFORGE.copy()
        django_settings.TOKENFORGE = {**original, "USER_CACHE_TTL": 300}
        reload_settings()

        try:
            # Manually place an inactive user object directly in the cache
            from django.core.cache import cache as _cache

            user.is_active = False
            _cache.set(f"tokenforge:user:{user.id}", user, timeout=300)

            request = factory.get("/")
            request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
            with pytest.raises(AuthenticationFailed):
                auth.authenticate(request)
        finally:
            django_settings.TOKENFORGE = original
            reload_settings()

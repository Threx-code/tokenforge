"""
Tests for tokenforge.services.exchange — create, redeem, counters.
"""

from contextlib import contextmanager
from unittest import mock

import pytest
from django.conf import settings as dj_settings
from django.core.cache import cache
from django.test import override_settings

from tokenforge.services.exchange import ExchangeTokenService
from tokenforge.settings import reload_settings

# ── Helpers ───────────────────────────────────────────────────────────────────


def make_exchange_token(
    user_id="user-123",
    device_session_id="sess-456",
    fingerprint="fp-abc",
    target_origin="https://app.example.com",
):
    return ExchangeTokenService.create(
        user_id=user_id,
        device_session_id=device_session_id,
        fingerprint=fingerprint,
        target_origin=target_origin,
    )


@contextmanager
def tf_settings(**overrides):
    merged = {**getattr(dj_settings, "TOKENFORGE", {}), **overrides}
    cm = override_settings(TOKENFORGE=merged)
    cm.enable()
    reload_settings()
    try:
        yield
    finally:
        cm.disable()
        reload_settings()


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear the cache before every test for isolation, and allowlist the test
    origin (exchange creation is fail-closed when EXCHANGE_ALLOWED_ORIGINS is
    unset)."""
    cache.clear()
    with tf_settings(EXCHANGE_ALLOWED_ORIGINS=["https://app.example.com"]):
        yield
    cache.clear()


# ── ExchangeTokenService.create ─────────────────────────────────────────────────────


class TestCreateExchangeToken:
    def test_returns_non_empty_string(self):
        token = make_exchange_token()
        assert isinstance(token, str)
        assert len(token) > 0

    def test_different_calls_return_different_tokens(self):
        t1 = make_exchange_token()
        t2 = make_exchange_token()
        assert t1 != t2

    def test_token_is_stored_in_cache(self):
        token = make_exchange_token()
        from tokenforge.tokens import OneTimeStore

        assert cache.get(OneTimeStore("exchange")._key(token)) is not None

    def test_payload_contains_user_id(self):
        token = make_exchange_token(user_id="uid-999")
        payload = ExchangeTokenService.redeem(token=token, request_origin="https://app.example.com")
        assert payload["sub"] == "uid-999"

    def test_payload_contains_session_id(self):
        token = make_exchange_token(device_session_id="sess-777")
        payload = ExchangeTokenService.redeem(token=token, request_origin="https://app.example.com")
        assert payload["sid"] == "sess-777"

    def test_payload_contains_fingerprint(self):
        token = make_exchange_token(fingerprint="fp-stored")
        payload = ExchangeTokenService.redeem(token=token, request_origin="https://app.example.com")
        assert payload["fp"] == "fp-stored"

    def test_target_origin_normalized_to_lowercase(self):
        token = ExchangeTokenService.create(
            user_id="u1",
            device_session_id="s1",
            target_origin="HTTPS://APP.EXAMPLE.COM",
        )
        # Redeeming with the lowercase form should work
        payload = ExchangeTokenService.redeem(token=token, request_origin="https://app.example.com")
        assert payload["sub"] == "u1"


# ── ExchangeTokenService.redeem ─────────────────────────────────────────────────────


class TestRedeemExchangeToken:
    def test_valid_token_returns_payload_dict(self):
        token = make_exchange_token()
        payload = ExchangeTokenService.redeem(token=token, request_origin="https://app.example.com")
        assert isinstance(payload, dict)
        assert "sub" in payload
        assert "sid" in payload

    def test_token_is_single_use(self):
        token = make_exchange_token()
        ExchangeTokenService.redeem(token=token, request_origin="https://app.example.com")
        with pytest.raises(ValueError, match="invalid or expired"):
            ExchangeTokenService.redeem(token=token, request_origin="https://app.example.com")

    def test_invalid_token_raises(self):
        with pytest.raises(ValueError, match="invalid or expired"):
            ExchangeTokenService.redeem(
                token="this-token-does-not-exist",
                request_origin="https://app.example.com",
            )

    def test_empty_token_raises(self):
        with pytest.raises(ValueError, match="required"):
            ExchangeTokenService.redeem(token="", request_origin="https://app.example.com")

    def test_origin_mismatch_raises(self):
        token = make_exchange_token(target_origin="https://app.example.com")
        with pytest.raises(ValueError, match="origin mismatch"):
            ExchangeTokenService.redeem(token=token, request_origin="https://evil.example.com")

    def test_missing_origin_header_raises_when_target_set(self):
        token = make_exchange_token(target_origin="https://app.example.com")
        with pytest.raises(ValueError, match="origin verification failed"):
            ExchangeTokenService.redeem(token=token, request_origin="")

    def test_origin_matching_succeeds(self):
        token = make_exchange_token(target_origin="https://app.example.com")
        payload = ExchangeTokenService.redeem(token=token, request_origin="https://app.example.com")
        assert payload["sub"] == "user-123"

    def test_trailing_slash_in_request_origin_normalised(self):
        token = make_exchange_token(target_origin="https://app.example.com")
        # The normalizer strips trailing slashes
        payload = ExchangeTokenService.redeem(
            token=token, request_origin="https://app.example.com/"
        )
        assert payload["sub"] == "user-123"

    def test_token_deleted_from_cache_after_redeem(self):
        token = make_exchange_token()
        from tokenforge.tokens import OneTimeStore

        ExchangeTokenService.redeem(token=token, request_origin="https://app.example.com")
        assert cache.get(OneTimeStore("exchange")._key(token)) is None

    def test_token_deleted_even_on_origin_mismatch(self):
        """Token is consumed (deleted) before origin check so it cannot be retried."""
        token = make_exchange_token(target_origin="https://app.example.com")
        from tokenforge.tokens import OneTimeStore

        with pytest.raises(ValueError):
            ExchangeTokenService.redeem(token=token, request_origin="https://evil.example.com")
        # Token must be gone from cache
        assert cache.get(OneTimeStore("exchange")._key(token)) is None


# ── active-token count (onetime-backed, pruned-on-read) ───────────────────────


class TestExchangeActiveCount:
    def test_initial_count_is_zero(self):
        assert ExchangeTokenService.count_active("user-new") == 0

    def test_create_increases_count(self):
        make_exchange_token(user_id="user-abc")
        assert ExchangeTokenService.count_active("user-abc") == 1

    def test_multiple_creates(self):
        for _ in range(3):
            make_exchange_token(user_id="user-multi")
        assert ExchangeTokenService.count_active("user-multi") == 3

    def test_redeem_releases_count(self):
        token = make_exchange_token(user_id="user-123")
        assert ExchangeTokenService.count_active("user-123") == 1
        ExchangeTokenService.redeem(token=token, request_origin="https://app.example.com")
        assert ExchangeTokenService.count_active("user-123") == 0

    def test_count_released_even_on_origin_failure(self):
        """The active count is released even when redemption fails validation."""
        token = make_exchange_token(user_id="user-123", target_origin="https://app.example.com")
        assert ExchangeTokenService.count_active("user-123") == 1
        with pytest.raises(ValueError):
            ExchangeTokenService.redeem(token=token, request_origin="https://evil.example.com")
        assert ExchangeTokenService.count_active("user-123") == 0

    def test_expired_token_stops_counting(self):
        """The drift fix: an unredeemed token that times out no longer counts
        (the old integer counter would have stayed incremented forever)."""
        real_now = __import__("time").time()
        make_exchange_token(user_id="user-exp")
        assert ExchangeTokenService.count_active("user-exp") == 1
        # Jump past the exchange TTL — the pruned-on-read set drops it.
        with mock.patch("tokenforge.tokens.onetime.time.time", return_value=real_now + 10_000):
            assert ExchangeTokenService.count_active("user-exp") == 0

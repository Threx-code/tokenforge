"""
Tests for tokenforge.services.exchange — create, redeem, counters.
"""

import pytest
from django.core.cache import cache

from tokenforge.services.exchange import (
    count_active_exchange_tokens,
    create_exchange_token,
    decrement_exchange_counter,
    increment_exchange_counter,
    redeem_exchange_token,
)

# ── Helpers ───────────────────────────────────────────────────────────────────


def make_exchange_token(
    user_id="user-123",
    device_session_id="sess-456",
    fingerprint="fp-abc",
    target_origin="https://app.example.com",
):
    return create_exchange_token(
        user_id=user_id,
        device_session_id=device_session_id,
        fingerprint=fingerprint,
        target_origin=target_origin,
    )


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear the cache before every test for isolation."""
    cache.clear()
    yield
    cache.clear()


# ── create_exchange_token ─────────────────────────────────────────────────────


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
        from tokenforge.services.exchange import _cache_key

        assert cache.get(_cache_key(token)) is not None

    def test_payload_contains_user_id(self):
        token = make_exchange_token(user_id="uid-999")
        payload = redeem_exchange_token(token=token, request_origin="https://app.example.com")
        assert payload["sub"] == "uid-999"

    def test_payload_contains_session_id(self):
        token = make_exchange_token(device_session_id="sess-777")
        payload = redeem_exchange_token(token=token, request_origin="https://app.example.com")
        assert payload["sid"] == "sess-777"

    def test_payload_contains_fingerprint(self):
        token = make_exchange_token(fingerprint="fp-stored")
        payload = redeem_exchange_token(token=token, request_origin="https://app.example.com")
        assert payload["fp"] == "fp-stored"

    def test_target_origin_normalized_to_lowercase(self):
        token = create_exchange_token(
            user_id="u1",
            device_session_id="s1",
            target_origin="HTTPS://APP.EXAMPLE.COM",
        )
        # Redeeming with the lowercase form should work
        payload = redeem_exchange_token(token=token, request_origin="https://app.example.com")
        assert payload["sub"] == "u1"


# ── redeem_exchange_token ─────────────────────────────────────────────────────


class TestRedeemExchangeToken:
    def test_valid_token_returns_payload_dict(self):
        token = make_exchange_token()
        payload = redeem_exchange_token(token=token, request_origin="https://app.example.com")
        assert isinstance(payload, dict)
        assert "sub" in payload
        assert "sid" in payload

    def test_token_is_single_use(self):
        token = make_exchange_token()
        redeem_exchange_token(token=token, request_origin="https://app.example.com")
        with pytest.raises(ValueError, match="invalid or expired"):
            redeem_exchange_token(token=token, request_origin="https://app.example.com")

    def test_invalid_token_raises(self):
        with pytest.raises(ValueError, match="invalid or expired"):
            redeem_exchange_token(
                token="this-token-does-not-exist",
                request_origin="https://app.example.com",
            )

    def test_empty_token_raises(self):
        with pytest.raises(ValueError, match="required"):
            redeem_exchange_token(token="", request_origin="https://app.example.com")

    def test_origin_mismatch_raises(self):
        token = make_exchange_token(target_origin="https://app.example.com")
        with pytest.raises(ValueError, match="origin mismatch"):
            redeem_exchange_token(token=token, request_origin="https://evil.example.com")

    def test_missing_origin_header_raises_when_target_set(self):
        token = make_exchange_token(target_origin="https://app.example.com")
        with pytest.raises(ValueError, match="origin verification failed"):
            redeem_exchange_token(token=token, request_origin="")

    def test_origin_matching_succeeds(self):
        token = make_exchange_token(target_origin="https://app.example.com")
        payload = redeem_exchange_token(token=token, request_origin="https://app.example.com")
        assert payload["sub"] == "user-123"

    def test_trailing_slash_in_request_origin_normalised(self):
        token = make_exchange_token(target_origin="https://app.example.com")
        # The normalizer strips trailing slashes
        payload = redeem_exchange_token(token=token, request_origin="https://app.example.com/")
        assert payload["sub"] == "user-123"

    def test_token_deleted_from_cache_after_redeem(self):
        token = make_exchange_token()
        from tokenforge.services.exchange import _cache_key

        redeem_exchange_token(token=token, request_origin="https://app.example.com")
        assert cache.get(_cache_key(token)) is None

    def test_token_deleted_even_on_origin_mismatch(self):
        """Token is consumed (deleted) before origin check so it cannot be retried."""
        token = make_exchange_token(target_origin="https://app.example.com")
        from tokenforge.services.exchange import _cache_key

        with pytest.raises(ValueError):
            redeem_exchange_token(token=token, request_origin="https://evil.example.com")
        # Token must be gone from cache
        assert cache.get(_cache_key(token)) is None


# ── counter helpers ───────────────────────────────────────────────────────────


class TestExchangeCounters:
    def test_initial_count_is_zero(self):
        assert count_active_exchange_tokens("user-new") == 0

    def test_increment_increases_count(self):
        increment_exchange_counter("user-abc")
        assert count_active_exchange_tokens("user-abc") == 1

    def test_multiple_increments(self):
        for _ in range(3):
            increment_exchange_counter("user-multi")
        assert count_active_exchange_tokens("user-multi") == 3

    def test_decrement_decreases_count(self):
        increment_exchange_counter("user-dec")
        increment_exchange_counter("user-dec")
        decrement_exchange_counter("user-dec")
        assert count_active_exchange_tokens("user-dec") == 1

    def test_decrement_to_zero_removes_key(self):
        increment_exchange_counter("user-zero")
        decrement_exchange_counter("user-zero")
        assert count_active_exchange_tokens("user-zero") == 0

    def test_decrement_on_missing_key_does_not_raise(self):
        # Should not raise even when counter key doesn't exist
        decrement_exchange_counter("user-nonexistent")

    def test_redeem_decrements_counter(self):
        """Redeeming a token should automatically decrement the counter."""
        increment_exchange_counter("user-123")
        assert count_active_exchange_tokens("user-123") == 1
        token = make_exchange_token(user_id="user-123")
        redeem_exchange_token(token=token, request_origin="https://app.example.com")
        assert count_active_exchange_tokens("user-123") == 0

    def test_counter_decremented_even_on_origin_failure(self):
        """Counter must be decremented even when origin validation fails."""
        increment_exchange_counter("user-123")
        token = make_exchange_token(user_id="user-123", target_origin="https://app.example.com")
        with pytest.raises(ValueError):
            redeem_exchange_token(token=token, request_origin="https://evil.example.com")
        assert count_active_exchange_tokens("user-123") == 0

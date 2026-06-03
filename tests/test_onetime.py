"""Tests for tokenforge.tokens.OneTimeStore — the atomic single-use primitive (H3)."""

from unittest import mock

from django.core.cache import cache

from tokenforge.tokens import OneTimeStore


class TestOnetime:
    def setup_method(self) -> None:
        cache.clear()

    def test_create_then_claim_roundtrips(self) -> None:
        store = OneTimeStore("t")
        token = store.create({"sub": "u1", "n": 2}, ttl=60)
        assert store.claim(token) == {"sub": "u1", "n": 2}

    def test_claim_is_single_use(self) -> None:
        store = OneTimeStore("t")
        token = store.create({"x": 1}, ttl=60)
        assert store.claim(token) == {"x": 1}
        assert store.claim(token) is None  # already consumed

    def test_claim_unknown_token_returns_none(self) -> None:
        assert OneTimeStore("t").claim("does-not-exist") is None

    def test_claim_empty_token_returns_none(self) -> None:
        assert OneTimeStore("t").claim("") is None

    def test_namespaces_are_isolated(self) -> None:
        token = OneTimeStore("a").create({"x": 1}, ttl=60)
        assert OneTimeStore("b").claim(token) is None  # wrong namespace
        assert OneTimeStore("a").claim(token) == {"x": 1}

    def test_corrupt_payload_returns_none(self) -> None:
        store = OneTimeStore("t")
        cache.set(store._key("tok"), "not-json{", timeout=60)
        assert store.claim("tok") is None

    def test_race_is_arbitrated_by_delete_not_get(self) -> None:
        """The exploit case: two concurrent claimers both pass cache.get before
        either deletes. With get forced to keep returning the value, the real
        atomic delete must still let exactly one caller win."""
        store = OneTimeStore("t")
        token = store.create({"x": 1}, ttl=60)
        raw = cache.get(store._key(token))

        with mock.patch("tokenforge.tokens.onetime.cache.get", return_value=raw):
            results = [store.claim(token), store.claim(token)]

        winners = [r for r in results if r is not None]
        assert len(winners) == 1
        assert winners[0] == {"x": 1}

"""
Tests for tokenforge.tokens — access token creation and verification.
"""

import time

import pytest
from django.core.exceptions import ImproperlyConfigured

from tokenforge.tokens import AccessToken

# ── Helpers ───────────────────────────────────────────────────────────────────


def make_token(**kwargs):
    """Create a valid access token with sensible defaults."""
    defaults = {"user_id": "test-user-id", "device_session_id": "sess-1", "fingerprint": "fp-abc"}
    defaults.update(kwargs)
    return AccessToken.create(**defaults)


# ── b64url helpers ────────────────────────────────────────────────────────────


class TestB64UrlHelpers:
    def test_roundtrip(self):
        data = b"hello world \x00\xff"
        assert AccessToken._b64url_decode(AccessToken._b64url_encode(data)) == data

    def test_no_padding_chars(self):
        encoded = AccessToken._b64url_encode(b"any bytes")
        assert "=" not in encoded

    def test_url_safe_chars(self):
        encoded = AccessToken._b64url_encode(b"\xff\xfe\xfd\xfc")
        assert "+" not in encoded
        assert "/" not in encoded


# ── AccessToken.create ───────────────────────────────────────────────────────


class TestCreateAccessToken:
    def test_returns_tuple_of_token_and_lifetime(self):
        token, lifetime = make_token()
        assert isinstance(token, str)
        assert isinstance(lifetime, int)
        assert lifetime > 0

    def test_token_has_two_parts(self):
        token, _ = make_token()
        parts = token.split(".")
        assert len(parts) == 2

    def test_payload_contains_expected_fields(self):
        token, _ = make_token(user_id="uid-123", device_session_id="sid-456", fingerprint="fp_xyz")
        payload = AccessToken.verify(token)
        assert payload["sub"] == "uid-123"
        assert payload["sid"] == "sid-456"
        assert payload["v"] == "v2"
        assert "iat" in payload
        assert "exp" in payload

    def test_fingerprint_truncated_to_16_chars(self):
        fp = "a" * 40
        token, _ = make_token(fingerprint=fp)
        payload = AccessToken.verify(token)
        assert payload["fp"] == "a" * 16

    def test_empty_fingerprint_stored_as_empty_string(self):
        token, _ = make_token(fingerprint="")
        payload = AccessToken.verify(token)
        assert payload["fp"] == ""

    def test_tenant_slug_stored(self):
        token, _ = AccessToken.create(user_id="u1", tenant_slug="acme")
        payload = AccessToken.verify(token)
        assert payload["tnt"] == "acme"

    def test_no_tenant_slug_defaults_to_empty(self):
        token, _ = make_token()
        payload = AccessToken.verify(token)
        assert payload["tnt"] == ""

    def test_exp_is_in_future(self):
        token, lifetime = make_token()
        payload = AccessToken.verify(token)
        assert payload["exp"] > int(time.time())

    def test_different_user_ids_produce_different_tokens(self):
        """Tokens with different sub claims must differ (distinct payloads)."""
        t1, _ = make_token(user_id="user-aaa")
        t2, _ = make_token(user_id="user-bbb")
        assert t1 != t2

    def test_raises_if_no_signing_key(self, settings):
        settings.TOKENFORGE = {
            "ACCESS_TOKEN_SIGNING_KEY": None,
            "REFRESH_TOKEN_COOKIE_SECURE": False,
        }
        from tokenforge.settings import reload_settings

        reload_settings()
        with pytest.raises(ImproperlyConfigured):
            make_token()
        # Restore
        settings.TOKENFORGE = {
            "ACCESS_TOKEN_SIGNING_KEY": "test-signing-key-not-for-production-use",
            "REFRESH_TOKEN_COOKIE_SECURE": False,
        }
        reload_settings()


# ── AccessToken.verify ───────────────────────────────────────────────────────


class TestVerifyAccessToken:
    def test_valid_token_returns_payload(self):
        token, _ = make_token(user_id="uid-999")
        payload = AccessToken.verify(token)
        assert payload["sub"] == "uid-999"

    def test_missing_dot_raises(self):
        with pytest.raises(ValueError, match="Malformed"):
            AccessToken.verify("nodotinhere")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Malformed"):
            AccessToken.verify("")

    def test_too_many_parts_raises(self):
        with pytest.raises(ValueError, match="Malformed"):
            AccessToken.verify("a.b.c")

    def test_tampered_signature_raises(self):
        token, _ = make_token()
        parts = token.split(".")
        bad_token = parts[0] + ".invalidsignatureXXX"
        with pytest.raises(ValueError, match="Invalid access token signature"):
            AccessToken.verify(bad_token)

    def test_tampered_payload_raises(self):
        token, _ = make_token()
        parts = token.split(".")
        # Corrupt the payload base64
        bad_token = "AAAAAAAAAAAAAAAA." + parts[1]
        with pytest.raises(ValueError):
            AccessToken.verify(bad_token)

    def test_expired_token_raises(self):
        import json

        from tokenforge.tokens import AccessToken

        now = int(time.time())
        payload = {
            "sub": "u1",
            "sid": "",
            "fp": "",
            "tnt": "",
            "iat": now - 1000,
            "exp": now - 500,
            "v": "v2",
        }
        payload_b64 = AccessToken._b64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        sig = AccessToken._compute_signature(payload_b64)
        token = f"{payload_b64}.{sig}"
        with pytest.raises(ValueError, match="expired"):
            AccessToken.verify(token)

    def test_future_iat_raises(self):
        import json

        from tokenforge.tokens import AccessToken

        now = int(time.time())
        payload = {
            "sub": "u1",
            "sid": "",
            "fp": "",
            "tnt": "",
            "iat": now + 9999,
            "exp": now + 10900,
            "v": "v2",
        }
        payload_b64 = AccessToken._b64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        sig = AccessToken._compute_signature(payload_b64)
        token = f"{payload_b64}.{sig}"
        with pytest.raises(ValueError, match="future"):
            AccessToken.verify(token)

    def test_matching_fingerprint_passes(self):
        fp = "a" * 40
        token, _ = make_token(fingerprint=fp)
        # Same fingerprint — should pass silently
        payload = AccessToken.verify(token, request_fingerprint=fp)
        assert payload["sub"] == "test-user-id"

    def test_mismatched_fingerprint_soft_warns_by_default(self):
        token, _ = make_token(fingerprint="aaaa" * 10)
        # Different fingerprint — should NOT raise (soft check only)
        payload = AccessToken.verify(token, request_fingerprint="bbbb" * 10)
        assert payload["sub"] == "test-user-id"

    def test_mismatched_fingerprint_raises_in_strict_mode(self, settings):
        settings.TOKENFORGE = {
            "ACCESS_TOKEN_SIGNING_KEY": "test-signing-key-not-for-production-use",
            "REFRESH_TOKEN_COOKIE_SECURE": False,
            "FINGERPRINT_STRICT_ACCESS_TOKEN": True,
        }
        from tokenforge.settings import reload_settings

        reload_settings()
        token, _ = make_token(fingerprint="aaaa" * 10)
        with pytest.raises(ValueError, match="fingerprint mismatch"):
            AccessToken.verify(token, request_fingerprint="bbbb" * 10)
        # Restore
        settings.TOKENFORGE = {
            "ACCESS_TOKEN_SIGNING_KEY": "test-signing-key-not-for-production-use",
            "REFRESH_TOKEN_COOKIE_SECURE": False,
        }
        reload_settings()

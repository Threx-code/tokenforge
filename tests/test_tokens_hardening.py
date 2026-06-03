"""v1.1 hardening tests for access-token verification (L1, L3, L6)."""

import json
import time

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from tokenforge.settings import reload_settings
from tokenforge.tokens import AccessToken


class TestL1MalformedNeverCrashes:
    """A malformed token must surface as ValueError (→ 401), never a TypeError
    that escapes as a 500."""

    def test_non_ascii_signature_raises_valueerror(self) -> None:
        with pytest.raises(ValueError):
            AccessToken.verify("payload.éésig")

    def test_non_ascii_payload_raises_valueerror(self) -> None:
        with pytest.raises(ValueError):
            AccessToken.verify("péyload.sig")

    def test_garbage_raises_valueerror(self) -> None:
        with pytest.raises(ValueError):
            AccessToken.verify("not-a-token")

    def test_too_many_segments_raises_valueerror(self) -> None:
        with pytest.raises(ValueError):
            AccessToken.verify("a.b.c")


class TestL3KeyStrength:
    def test_short_signing_key_is_rejected(self) -> None:
        try:
            with override_settings(TOKENFORGE={"ACCESS_TOKEN_SIGNING_KEY": "short-key"}):
                reload_settings()
                with pytest.raises(ImproperlyConfigured):
                    AccessToken.create(user_id="u1")
        finally:
            # Restore AFTER the override exits, so we reload the real key —
            # otherwise the short key leaks into subsequent tests.
            reload_settings()

    def test_long_signing_key_is_accepted(self) -> None:
        # The test settings key is >= 32 bytes; a normal token round-trips.
        token, _ = AccessToken.create(user_id="u1", device_session_id="s1")
        assert AccessToken.verify(token)["sub"] == "u1"


class TestL6FormatVersion:
    def test_unknown_format_version_is_rejected(self) -> None:
        now = int(time.time())
        payload = {
            "sub": "u",
            "sid": "s",
            "fp": "",
            "tnt": "",
            "iat": now,
            "exp": now + 900,
            "v": "bogus",
        }
        pb = AccessToken._b64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        token = (
            f"{pb}.{AccessToken._compute_signature(pb)}"  # correctly signed, but unknown version
        )
        with pytest.raises(ValueError):
            AccessToken.verify(token)

    def test_current_format_version_is_accepted(self) -> None:
        token, _ = AccessToken.create(user_id="u1")
        assert AccessToken.verify(token)["v"] == "v2"

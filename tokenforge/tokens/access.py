"""
Stateless Access Token — HMAC-SHA256 signed, no DB lookup per request.

Format: base64url(json_payload).base64url(hmac_signature)

The access token is short-lived (15 min default) and contains:
  sub: user UUID
  sid: device session UUID
  fp:  first 16 chars of fingerprint hash (for binding verification)
  tnt: tenant slug (optional)
  iat: issued-at unix timestamp
  exp: expiry unix timestamp
  v:   auth version
  jti: unique token id (denylist kill-switch + audit)
"""

import base64
import hashlib
import hmac
import json
import logging
import time
import uuid

from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger("tokenforge")


class AccessToken:
    """Codec for the stateless HMAC-SHA256 access token.

    Stateless (the signing key is global config), so the public surface is
    classmethods: ``AccessToken.create(...)`` and ``AccessToken.verify(...)``.
    """

    # Access-token wire-format version stamped into the ``v`` claim. This is the
    # format that has shipped since 1.0.0, so it stays "v2" for backward
    # compatibility — changing it would invalidate every token already in flight.
    # New formats add their string to the accepted set.
    FORMAT_VERSION = "v2"
    _ACCEPTED_VERSIONS = frozenset({FORMAT_VERSION})

    # Minimum HMAC signing-key length. A short key weakens every token; fail loudly.
    _MIN_SIGNING_KEY_BYTES = 32

    # ── encoding helpers ─────────────────────────────────
    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return base64.urlsafe_b64decode(s)

    # ── signing ──────────────────────────────────────────
    @classmethod
    def _signing_key(cls) -> bytes:
        from tokenforge.settings import tokenforge_settings

        key = tokenforge_settings.ACCESS_TOKEN_SIGNING_KEY
        if not key:
            raise ImproperlyConfigured(
                "TOKENFORGE['ACCESS_TOKEN_SIGNING_KEY'] is not set. "
                "Generate a dedicated key with: openssl rand -base64 64 "
                "and add it to your environment. "
                "Never share this key with SECRET_KEY."
            )
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        if len(key_bytes) < cls._MIN_SIGNING_KEY_BYTES:
            raise ImproperlyConfigured(
                f"TOKENFORGE['ACCESS_TOKEN_SIGNING_KEY'] is too short "
                f"({len(key_bytes)} bytes); it must be at least {cls._MIN_SIGNING_KEY_BYTES} bytes. "
                "Generate one with: openssl rand -base64 64"
            )
        return key_bytes

    @classmethod
    def _compute_signature(cls, payload_b64: str) -> str:
        sig = hmac.new(cls._signing_key(), payload_b64.encode("ascii"), hashlib.sha256).digest()
        return cls._b64url_encode(sig)

    # ── public API ───────────────────────────────────────
    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        device_session_id: str = "",
        fingerprint: str = "",
        tenant_slug: str | None = None,
    ) -> tuple[str, int]:
        """Create a signed access token. Returns (token_string, expires_in_seconds)."""
        from tokenforge.settings import tokenforge_settings

        lifetime = tokenforge_settings.ACCESS_TOKEN_LIFETIME_SECONDS
        now = int(time.time())

        payload = {
            "sub": str(user_id),
            "sid": str(device_session_id),
            "fp": fingerprint[:16] if fingerprint else "",
            "tnt": tenant_slug or "",
            "iat": now,
            "exp": now + lifetime,
            "v": cls.FORMAT_VERSION,
            # Unique token id — enables the optional denylist kill-switch and audit.
            # Optional on verify (tokens minted before 1.4 have none), so adding it
            # is backward compatible.
            "jti": uuid.uuid4().hex,
        }

        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        payload_b64 = cls._b64url_encode(payload_json.encode("utf-8"))
        signature = cls._compute_signature(payload_b64)

        return f"{payload_b64}.{signature}", lifetime

    @classmethod
    def verify(
        cls, token_string: str, *, request_fingerprint: str | None = None
    ) -> dict[str, object]:
        """Verify and decode an access token.

        Returns the payload dict on success. Raises ValueError on any failure.
        """
        if not token_string or "." not in token_string:
            raise ValueError("Malformed access token")

        parts = token_string.split(".")
        if len(parts) != 2:
            raise ValueError("Malformed access token")

        payload_b64, provided_sig = parts

        # Both segments are base64url (ASCII). hmac.compare_digest raises TypeError
        # on a non-ASCII str — guard here so a malformed token always surfaces as a
        # ValueError (→ 401) instead of escaping as an unhandled 500.
        if not payload_b64.isascii() or not provided_sig.isascii():
            raise ValueError("Malformed access token")

        # Verify HMAC signature (constant-time comparison)
        expected_sig = cls._compute_signature(payload_b64)
        if not hmac.compare_digest(provided_sig, expected_sig):
            raise ValueError("Invalid access token signature")

        # Decode payload
        try:
            payload_json = cls._b64url_decode(payload_b64)
            payload = json.loads(payload_json)
        except Exception as e:
            raise ValueError("Invalid access token payload") from e

        # Check required fields
        for field in ("sub", "sid", "fp", "iat", "exp", "v"):
            if field not in payload:
                raise ValueError(f"Missing field in access token: {field}")

        # Validate the wire-format version. Signed, so not attacker-forgeable, but
        # rejecting unknown versions prevents an old verifier from misreading a
        # future token format (forward-compatible safety).
        if payload["v"] not in cls._ACCEPTED_VERSIONS:
            raise ValueError("Unsupported access token format version")

        # Check expiry
        now = int(time.time())
        if now >= payload["exp"]:
            raise ValueError("Access token expired")

        # Check not issued in the future (clock skew tolerance: 30 seconds)
        if payload["iat"] > now + 30:
            raise ValueError("Access token issued in the future")

        # Verify fingerprint binding (soft check by default — warn only on access tokens).
        #
        # Hard-failing here causes legitimate session drops for:
        #   - Mobile users switching between WiFi and LTE (IP change)
        #   - Corporate proxies that rotate IPs per request
        #   - VPN users changing exit nodes
        #
        # The recommended device-binding boundary is REFRESH ROTATION: set
        # TOKENFORGE["FINGERPRINT_STRICT_REFRESH"] = True (on by default in 2.0) to
        # hard-fail there. Set TOKENFORGE["FINGERPRINT_STRICT_ACCESS_TOKEN"] = True
        # to hard-fail on access tokens too, if your deployment has stable IPs.
        if request_fingerprint:
            from tokenforge.settings import tokenforge_settings as _ts

            token_fp = payload.get("fp", "")
            request_fp_prefix = request_fingerprint[:16] if request_fingerprint else ""
            if (
                token_fp
                and request_fp_prefix
                and not hmac.compare_digest(token_fp, request_fp_prefix)
            ):
                logger.warning(
                    "Access token fingerprint drift: token_fp=%s, request_fp=%s, user=%s "
                    "(soft-warn only — hard-fail is enforced at refresh rotation)",
                    token_fp[:8] + "...",
                    request_fp_prefix[:8] + "...",
                    payload.get("sub"),
                )
                if getattr(_ts, "FINGERPRINT_STRICT_ACCESS_TOKEN", False):
                    raise ValueError("Access token fingerprint mismatch")

        return payload  # type: ignore[no-any-return]

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
"""

import base64
import hashlib
import hmac
import json
import logging
import time

from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger("tokenforge")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _get_signing_key() -> bytes:
    from tokenforge.settings import tokenforge_settings

    key = tokenforge_settings.ACCESS_TOKEN_SIGNING_KEY
    if not key:
        raise ImproperlyConfigured(
            "TOKENFORGE['ACCESS_TOKEN_SIGNING_KEY'] is not set. "
            "Generate a dedicated key with: openssl rand -base64 64 "
            "and add it to your environment. "
            "Never share this key with SECRET_KEY."
        )
    return key.encode("utf-8") if isinstance(key, str) else key


def _compute_signature(payload_b64: str) -> str:
    sig = hmac.new(_get_signing_key(), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return _b64url_encode(sig)


def create_access_token(
    *,
    user_id: str,
    device_session_id: str = "",
    fingerprint: str = "",
    tenant_slug: str | None = None,
) -> tuple[str, int]:
    """
    Create a signed access token.

    Returns (token_string, expires_in_seconds).
    """
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
        "v": "v2",
    }

    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_b64 = _b64url_encode(payload_json.encode("utf-8"))
    signature = _compute_signature(payload_b64)

    return f"{payload_b64}.{signature}", lifetime


def verify_access_token(
    token_string: str, *, request_fingerprint: str | None = None
) -> dict[str, object]:
    """
    Verify and decode an access token.

    Returns the payload dict on success.
    Raises ValueError on any validation failure.
    """
    if not token_string or "." not in token_string:
        raise ValueError("Malformed access token")

    parts = token_string.split(".")
    if len(parts) != 2:
        raise ValueError("Malformed access token")

    payload_b64, provided_sig = parts

    # Verify HMAC signature (constant-time comparison)
    expected_sig = _compute_signature(payload_b64)
    if not hmac.compare_digest(provided_sig, expected_sig):
        raise ValueError("Invalid access token signature")

    # Decode payload
    try:
        payload_json = _b64url_decode(payload_b64)
        payload = json.loads(payload_json)
    except (json.JSONDecodeError, Exception) as e:
        raise ValueError("Invalid access token payload") from e

    # Check required fields
    for field in ("sub", "sid", "fp", "iat", "exp", "v"):
        if field not in payload:
            raise ValueError(f"Missing field in access token: {field}")

    # Check expiry
    now = int(time.time())
    if now >= payload["exp"]:
        raise ValueError("Access token expired")

    # Check not issued in the future (clock skew tolerance: 30 seconds)
    if payload["iat"] > now + 30:
        raise ValueError("Access token issued in the future")

    # Verify fingerprint binding (soft check — warn only, never hard-fail on access tokens).
    #
    # Hard-failing here causes legitimate session drops for:
    #   - Mobile users switching between WiFi and LTE (IP change)
    #   - Corporate proxies that rotate IPs per request
    #   - VPN users changing exit nodes
    #
    # Fingerprint drift is already enforced as a hard-fail during refresh token
    # rotation (services/refresh.py), which is the correct security boundary.
    # Here we only log the event so the risk handler / monitoring can react.
    #
    # Set TOKENFORGE["FINGERPRINT_STRICT_ACCESS_TOKEN"] = True to restore
    # hard-fail behaviour if your deployment has stable, trusted IPs.
    if request_fingerprint:
        from tokenforge.settings import tokenforge_settings as _ts

        token_fp = payload.get("fp", "")
        request_fp_prefix = request_fingerprint[:16] if request_fingerprint else ""
        if token_fp and request_fp_prefix and not hmac.compare_digest(token_fp, request_fp_prefix):
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

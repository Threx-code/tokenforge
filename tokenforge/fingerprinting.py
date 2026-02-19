"""
Request fingerprinting for device binding.

Computes a SHA-256 hash of client IP + User-Agent to bind tokens
to a specific device/network context. Used by:
  - BearerTokenAuthentication (fingerprint verification)
  - Refresh token rotation (fingerprint drift detection)
  - Login service (device fingerprinting)

Override via TOKENFORGE["FINGERPRINT_FUNCTION"].

X-Forwarded-For trust
---------------------
X-Forwarded-For is a client-controlled header and trivially spoofable unless
your reverse proxy strips and rewrites it. To extract the real client IP safely,
set NUM_PROXIES in Django settings to the number of trusted proxy hops in front
of the application server:

    # settings.py
    NUM_PROXIES = 1   # one nginx / ALB in front

With NUM_PROXIES = N, we take the Nth-from-right address in the XFF chain —
the last address added by a proxy we control — rather than blindly trusting
the leftmost value that the client can forge.

If NUM_PROXIES is 0 or unset, X-Forwarded-For is ignored entirely and
REMOTE_ADDR is used directly (safe for direct-to-server deployments).
"""

import hashlib
import logging

from django.conf import settings
from django.http import HttpRequest

logger = logging.getLogger("tokenforge")


def fingerprint_for_request(request: HttpRequest) -> str:
    """
    Compute a SHA-256 fingerprint from client IP + User-Agent.
    """
    ip_address = get_client_ip(request)
    user_agent = str(request.META.get("HTTP_USER_AGENT", ""))
    fingerprint_raw = f"{ip_address}|{user_agent}"
    return hashlib.sha256(fingerprint_raw.encode()).hexdigest()


def get_client_ip(request: HttpRequest) -> str:
    """
    Extract the real client IP.

    Trusts X-Forwarded-For only when NUM_PROXIES > 0 is set in Django settings,
    and reads the correct position from the right of the XFF chain to avoid
    client IP spoofing.
    """
    num_proxies = getattr(settings, "NUM_PROXIES", 0)

    if num_proxies and num_proxies > 0:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if x_forwarded_for:
            # XFF format: "client, proxy1, proxy2"
            # The last `num_proxies` entries were added by our infrastructure.
            # The entry just before them is the real client IP.
            ips = [ip.strip() for ip in x_forwarded_for.split(",")]
            # Guard: if the chain is shorter than expected, take the first entry
            # rather than an infrastructure IP.
            index = max(len(ips) - num_proxies, 0)
            client_ip: str = ips[index]
            if client_ip:
                return client_ip
            logger.warning(
                "X-Forwarded-For present but yielded empty IP at index %d: %s",
                index,
                x_forwarded_for,
            )

    # NUM_PROXIES is 0 / unset, or XFF header was absent — use the direct connection IP.
    return str(request.META.get("REMOTE_ADDR", ""))

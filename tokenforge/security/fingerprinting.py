"""
Request fingerprinting for device binding.

Computes a SHA-256 hash of the configured request components (UA-only by default
in 2.0) to bind tokens to a device/network context. Used by:
  - BearerTokenAuthentication (fingerprint verification)
  - Refresh token rotation (fingerprint drift detection)
  - Login service (device fingerprinting)

Usage:
    fp = RequestFingerprint(request).compute()
    ip = RequestFingerprint(request).client_ip()

A consumer can still plug in a different callable via
TOKENFORGE["FINGERPRINT_FUNCTION"] (any callable ``fn(request) -> str``); when
unset, this class is the default.

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


class RequestFingerprint:
    """Device fingerprint for a single request (the request is the instance state)."""

    def __init__(self, request: HttpRequest) -> None:
        self.request = request

    def compute(self) -> str:
        """SHA-256 fingerprint from the configured request components.

        Controlled by ``TOKENFORGE["FINGERPRINT_COMPONENTS"]`` (2.0 default
        ``["ua"]`` — a network-stable fingerprint that survives mobile/VPN/proxy
        IP changes, which matters now that FINGERPRINT_STRICT_REFRESH is on by
        default). Add ``"ip"`` for the historical IP + User-Agent binding if your
        clients have stable, trusted IPs.
        """
        from tokenforge.settings import tokenforge_settings

        components = tokenforge_settings.FINGERPRINT_COMPONENTS
        parts: list[str] = []
        if "ip" in components:
            parts.append(self.client_ip())
        if "ua" in components:
            parts.append(str(self.request.META.get("HTTP_USER_AGENT", "")))

        fingerprint_raw = "|".join(parts)
        return hashlib.sha256(fingerprint_raw.encode()).hexdigest()

    def client_ip(self) -> str:
        """Extract the real client IP.

        Trusts X-Forwarded-For only when NUM_PROXIES > 0 is set in Django
        settings, and reads the correct position from the right of the XFF chain
        to avoid client IP spoofing.
        """
        num_proxies = getattr(settings, "NUM_PROXIES", 0)

        if num_proxies and num_proxies > 0:
            x_forwarded_for = self.request.META.get("HTTP_X_FORWARDED_FOR", "")
            if x_forwarded_for:
                # XFF format: "client, proxy1, proxy2"
                # The last `num_proxies` entries were added by our infrastructure.
                # The entry just before them is the real client IP.
                ips = [ip.strip() for ip in x_forwarded_for.split(",")]
                # Guard: if the chain is shorter than expected, take the first
                # entry rather than an infrastructure IP.
                index = max(len(ips) - num_proxies, 0)
                client_ip: str = ips[index]
                if client_ip:
                    return client_ip
                logger.warning(
                    "X-Forwarded-For present but yielded empty IP at index %d: %s",
                    index,
                    x_forwarded_for,
                )

        # NUM_PROXIES is 0 / unset, or XFF header was absent — use the direct IP.
        return str(self.request.META.get("REMOTE_ADDR", ""))

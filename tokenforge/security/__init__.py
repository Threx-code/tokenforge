"""TokenForge request-security layer.

  authentication.py  — the DRF Bearer authentication class + user cache
  fingerprinting.py  — device fingerprint computation + client-IP extraction
  cookies.py         — the refresh cookie (set/expire + `__Secure-` name)

Public classes are re-exported here; the DRF ``DEFAULT_AUTHENTICATION_CLASSES``
dotted path is ``tokenforge.security.authentication.BearerTokenAuthentication``.
"""

from tokenforge.security.authentication import BearerTokenAuthentication, UserCache
from tokenforge.security.cookies import RefreshCookie
from tokenforge.security.fingerprinting import RequestFingerprint

__all__ = [
    "BearerTokenAuthentication",
    "UserCache",
    "RequestFingerprint",
    "RefreshCookie",
]

"""Shared base view for the tokenforge endpoints."""

import logging
from typing import Any

from django.db.models import Model
from rest_framework.generics import GenericAPIView
from rest_framework.request import Request

from tokenforge.security import RequestFingerprint

logger = logging.getLogger("tokenforge")


class BaseTokenView(GenericAPIView[Model]):
    """Base class for tokenforge views — shared server-side helpers.

    Concrete endpoints subclass this; it carries no routing of its own.
    """

    def resolve_tenant(self, request: Request, user: Any) -> str:
        """Resolve the `tnt` claim server-side via the optional TENANT_RESOLVER.

        Never sourced from a client header: a signed claim must not carry
        unvalidated client input. Returns "" when no resolver is configured.
        """
        from tokenforge.settings import tokenforge_settings

        resolver = tokenforge_settings.TENANT_RESOLVER
        if not resolver:
            return ""
        try:
            return str(resolver(request, user) or "")
        except Exception:  # a tenant-resolution failure must never block auth
            logger.warning("TENANT_RESOLVER raised; issuing token with empty tnt")
            return ""

    def request_fingerprint(self, request: Request) -> str:
        """Fingerprint for the current request — the FINGERPRINT_FUNCTION callable
        hook when configured, otherwise the built-in RequestFingerprint."""
        from tokenforge.settings import tokenforge_settings

        fingerprint_fn = tokenforge_settings.FINGERPRINT_FUNCTION
        if fingerprint_fn:
            return str(fingerprint_fn(request))
        return RequestFingerprint(request).compute()

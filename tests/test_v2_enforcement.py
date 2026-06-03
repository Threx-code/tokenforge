"""v1.2 enforcement tests — fingerprint hard-fail at refresh (H1) and the
server-resolved tenant claim (H2)."""

from contextlib import contextmanager
from typing import Any

import pytest
from django.conf import settings as dj_settings
from django.contrib.auth import get_user_model
from django.test import RequestFactory, override_settings
from rest_framework.test import APIClient

from tokenforge.security.fingerprinting import RequestFingerprint
from tokenforge.services.refresh import RefreshTokenService
from tokenforge.settings import reload_settings
from tokenforge.tokens import AccessToken

User = get_user_model()
pytestmark = pytest.mark.django_db


@contextmanager
def tf_settings(**overrides: Any):
    """Override TOKENFORGE keys (merged onto the test config) and reload."""
    merged = {**getattr(dj_settings, "TOKENFORGE", {}), **overrides}
    cm = override_settings(TOKENFORGE=merged)
    cm.enable()
    reload_settings()
    try:
        yield
    finally:
        cm.disable()
        reload_settings()


@pytest.fixture()
def user(db: Any) -> Any:
    return User.objects.create_user(username="enf_user", password="pass")


def tenant_resolver_stub(request: Any, user: Any) -> str:
    """Server-side TENANT_RESOLVER used by the H2 test (resolved via dotted path)."""
    return "acme"


# ── H1 — fingerprint hard-fail at refresh ─────────────────────────────────────


class TestFingerprintStrictRefresh:
    def test_drift_rejected_when_strict(self, user: Any) -> None:
        raw, _ = RefreshTokenService.create(user=user, fingerprint="fp-A")
        with tf_settings(FINGERPRINT_STRICT_REFRESH=True), pytest.raises(ValueError):
            RefreshTokenService.rotate(raw_token=raw, fingerprint="fp-B")

    def test_drift_rejected_by_default(self, user: Any) -> None:
        # 2.0 default: FINGERPRINT_STRICT_REFRESH is on, so drift hard-fails.
        raw, _ = RefreshTokenService.create(user=user, fingerprint="fp-A")
        with pytest.raises(ValueError):
            RefreshTokenService.rotate(raw_token=raw, fingerprint="fp-B")

    def test_drift_allowed_when_explicitly_soft(self, user: Any) -> None:
        raw, _ = RefreshTokenService.create(user=user, fingerprint="fp-A")
        with tf_settings(FINGERPRINT_STRICT_REFRESH=False):
            new_raw, _new = RefreshTokenService.rotate(raw_token=raw, fingerprint="fp-B")
        assert isinstance(new_raw, str)

    def test_matching_fingerprint_rotates_when_strict(self, user: Any) -> None:
        raw, _ = RefreshTokenService.create(user=user, fingerprint="fp-A")
        with tf_settings(FINGERPRINT_STRICT_REFRESH=True):
            new_raw, _new = RefreshTokenService.rotate(raw_token=raw, fingerprint="fp-A")
        assert isinstance(new_raw, str)

    def test_no_stored_fingerprint_is_not_drift(self, user: Any) -> None:
        # A token issued without a fingerprint must not hard-fail on rotation.
        raw, _ = RefreshTokenService.create(user=user, fingerprint="")
        with tf_settings(FINGERPRINT_STRICT_REFRESH=True):
            new_raw, _new = RefreshTokenService.rotate(raw_token=raw, fingerprint="fp-B")
        assert isinstance(new_raw, str)

    def test_per_call_false_overrides_global_true(self, user: Any) -> None:
        # The mobile path: global enforcement on, but this call opts out so a
        # network-driven fingerprint change does not log the user out.
        raw, _ = RefreshTokenService.create(user=user, fingerprint="fp-A")
        with tf_settings(FINGERPRINT_STRICT_REFRESH=True):
            new_raw, _new = RefreshTokenService.rotate(
                raw_token=raw, fingerprint="fp-B", strict_fingerprint=False
            )
        assert isinstance(new_raw, str)

    def test_per_call_true_overrides_global_false(self, user: Any) -> None:
        raw, _ = RefreshTokenService.create(user=user, fingerprint="fp-A")
        # Global forced soft, but this call forces strict → still raises.
        with tf_settings(FINGERPRINT_STRICT_REFRESH=False), pytest.raises(ValueError):
            RefreshTokenService.rotate(raw_token=raw, fingerprint="fp-B", strict_fingerprint=True)


# ── H1 — configurable fingerprint components ──────────────────────────────────


class TestFingerprintComponents:
    def setup_method(self) -> None:
        self.rf = RequestFactory()

    def test_ua_only_is_stable_across_ip_change(self) -> None:
        with tf_settings(FINGERPRINT_COMPONENTS=["ua"]):
            r1 = self.rf.get("/", HTTP_USER_AGENT="UA", REMOTE_ADDR="1.1.1.1")
            r2 = self.rf.get("/", HTTP_USER_AGENT="UA", REMOTE_ADDR="2.2.2.2")
            assert RequestFingerprint(r1).compute() == RequestFingerprint(r2).compute()

    def test_default_components_are_ua_only(self) -> None:
        # 2.0 default ["ua"]: an IP change does not alter the fingerprint.
        r1 = self.rf.get("/", HTTP_USER_AGENT="UA", REMOTE_ADDR="1.1.1.1")
        r2 = self.rf.get("/", HTTP_USER_AGENT="UA", REMOTE_ADDR="2.2.2.2")
        assert RequestFingerprint(r1).compute() == RequestFingerprint(r2).compute()

    def test_ip_included_when_configured(self) -> None:
        r1 = self.rf.get("/", HTTP_USER_AGENT="UA", REMOTE_ADDR="1.1.1.1")
        r2 = self.rf.get("/", HTTP_USER_AGENT="UA", REMOTE_ADDR="2.2.2.2")
        with tf_settings(FINGERPRINT_COMPONENTS=["ip", "ua"]):
            assert RequestFingerprint(r1).compute() != RequestFingerprint(r2).compute()


# ── H2 — tnt claim is server-resolved, never from a client header ─────────────


class TestTenantClaim:
    url = "/api/v1/auth/token/refresh/"

    def _refresh(self, user: Any, **extra: Any) -> Any:
        client = APIClient()
        raw, _ = RefreshTokenService.create(user=user, fingerprint="")
        client.cookies["refresh_token"] = raw
        return client.post(self.url, HTTP_X_REQUESTED_WITH="XMLHttpRequest", **extra)

    def test_client_tenant_header_is_ignored(self, user: Any) -> None:
        resp = self._refresh(user, HTTP_X_TENANT_SLUG="attacker-tenant")
        assert resp.status_code == 200
        payload = AccessToken.verify(resp.data["access_token"])
        assert payload["tnt"] == ""  # the client header must not reach the signed claim

    def test_resolver_sets_tenant(self, user: Any) -> None:
        with tf_settings(TENANT_RESOLVER="tests.test_v2_enforcement.tenant_resolver_stub"):
            resp = self._refresh(user, HTTP_X_TENANT_SLUG="attacker-tenant")
            assert resp.status_code == 200
            payload = AccessToken.verify(resp.data["access_token"])
            assert payload["tnt"] == "acme"  # server-resolved, not the header value

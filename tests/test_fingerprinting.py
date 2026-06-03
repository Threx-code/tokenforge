"""
Tests for tokenforge.security.fingerprinting — IP extraction and fingerprint hashing.
"""

import hashlib
from contextlib import contextmanager

from django.conf import settings as dj_settings
from django.test import RequestFactory, override_settings

from tokenforge.security.fingerprinting import RequestFingerprint
from tokenforge.settings import reload_settings

factory = RequestFactory()


@contextmanager
def fingerprint_components(*components):
    merged = {**getattr(dj_settings, "TOKENFORGE", {}), "FINGERPRINT_COMPONENTS": list(components)}
    cm = override_settings(TOKENFORGE=merged)
    cm.enable()
    reload_settings()
    try:
        yield
    finally:
        cm.disable()
        reload_settings()


def make_request(remote_addr="1.2.3.4", user_agent="TestAgent/1.0", xff=None):
    request = factory.get("/")
    request.META["REMOTE_ADDR"] = remote_addr
    request.META["HTTP_USER_AGENT"] = user_agent
    if xff:
        request.META["HTTP_X_FORWARDED_FOR"] = xff
    return request


# ── get_client_ip ─────────────────────────────────────────────────────────────


class TestGetClientIp:
    def test_uses_remote_addr_by_default(self):
        request = make_request(remote_addr="10.0.0.1")
        assert RequestFingerprint(request).client_ip() == "10.0.0.1"

    def test_ignores_xff_when_no_proxies_configured(self, settings):
        settings.NUM_PROXIES = 0
        request = make_request(remote_addr="10.0.0.1", xff="5.5.5.5")
        assert RequestFingerprint(request).client_ip() == "10.0.0.1"

    def test_uses_xff_when_num_proxies_set(self, settings):
        settings.NUM_PROXIES = 1
        # XFF = "client" only — 1 proxy appended the client IP, so
        # index = max(1 - 1, 0) = 0 → first (and only) entry is the client
        request = make_request(xff="5.5.5.5")
        assert RequestFingerprint(request).client_ip() == "5.5.5.5"

    def test_xff_with_two_proxies(self, settings):
        settings.NUM_PROXIES = 2
        # XFF = "real-client, proxy1" — 2 proxies: index = max(2-2,0)=0
        request = make_request(xff="real-client, proxy1")
        assert RequestFingerprint(request).client_ip() == "real-client"

    def test_xff_chain_shorter_than_proxies_takes_first(self, settings):
        settings.NUM_PROXIES = 5
        request = make_request(xff="only-one-ip")
        # index = max(1 - 5, 0) = 0 → first entry
        assert RequestFingerprint(request).client_ip() == "only-one-ip"

    def test_empty_xff_falls_back_to_remote_addr(self, settings):
        settings.NUM_PROXIES = 1
        request = make_request(remote_addr="9.9.9.9", xff="")
        assert RequestFingerprint(request).client_ip() == "9.9.9.9"

    def test_no_remote_addr_returns_empty_string(self):
        request = factory.get("/")
        request.META.pop("REMOTE_ADDR", None)
        result = RequestFingerprint(request).client_ip()
        assert result == ""


# ── fingerprint_for_request ───────────────────────────────────────────────────


class TestFingerprintForRequest:
    def test_returns_64_char_hex_string(self):
        request = make_request()
        fp = RequestFingerprint(request).compute()
        assert isinstance(fp, str)
        assert len(fp) == 64
        int(fp, 16)  # must be valid hex

    def test_same_inputs_produce_same_fingerprint(self):
        r1 = make_request(remote_addr="1.1.1.1", user_agent="UA/1")
        r2 = make_request(remote_addr="1.1.1.1", user_agent="UA/1")
        assert RequestFingerprint(r1).compute() == RequestFingerprint(r2).compute()

    def test_different_ip_produces_different_fingerprint(self):
        # IP is only part of the fingerprint when explicitly configured (the 2.0
        # default is ua-only).
        r1 = make_request(remote_addr="1.1.1.1", user_agent="UA/1")
        r2 = make_request(remote_addr="2.2.2.2", user_agent="UA/1")
        with fingerprint_components("ip", "ua"):
            assert RequestFingerprint(r1).compute() != RequestFingerprint(r2).compute()

    def test_ip_change_ignored_by_default(self):
        # Default ["ua"]: a network/IP change does NOT alter the fingerprint, so
        # strict refresh doesn't log mobile/VPN users out on a network switch.
        r1 = make_request(remote_addr="1.1.1.1", user_agent="UA/1")
        r2 = make_request(remote_addr="2.2.2.2", user_agent="UA/1")
        assert RequestFingerprint(r1).compute() == RequestFingerprint(r2).compute()

    def test_different_user_agent_produces_different_fingerprint(self):
        r1 = make_request(remote_addr="1.1.1.1", user_agent="Chrome/1")
        r2 = make_request(remote_addr="1.1.1.1", user_agent="Firefox/1")
        assert RequestFingerprint(r1).compute() != RequestFingerprint(r2).compute()

    def test_fingerprint_matches_manual_sha256_default_ua_only(self):
        request = make_request(remote_addr="3.3.3.3", user_agent="Bot/1.0")
        expected = hashlib.sha256(b"Bot/1.0").hexdigest()
        assert RequestFingerprint(request).compute() == expected

    def test_fingerprint_matches_manual_sha256_with_ip(self):
        request = make_request(remote_addr="3.3.3.3", user_agent="Bot/1.0")
        expected = hashlib.sha256(b"3.3.3.3|Bot/1.0").hexdigest()
        with fingerprint_components("ip", "ua"):
            assert RequestFingerprint(request).compute() == expected

    def test_missing_user_agent_does_not_raise(self):
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "1.2.3.4"
        # No HTTP_USER_AGENT set
        fp = RequestFingerprint(request).compute()
        assert len(fp) == 64

"""
Tests for tokenforge.fingerprinting — IP extraction and fingerprint hashing.
"""

import hashlib

from django.test import RequestFactory

from tokenforge.fingerprinting import fingerprint_for_request, get_client_ip

factory = RequestFactory()


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
        assert get_client_ip(request) == "10.0.0.1"

    def test_ignores_xff_when_no_proxies_configured(self, settings):
        settings.NUM_PROXIES = 0
        request = make_request(remote_addr="10.0.0.1", xff="5.5.5.5")
        assert get_client_ip(request) == "10.0.0.1"

    def test_uses_xff_when_num_proxies_set(self, settings):
        settings.NUM_PROXIES = 1
        # XFF = "client" only — 1 proxy appended the client IP, so
        # index = max(1 - 1, 0) = 0 → first (and only) entry is the client
        request = make_request(xff="5.5.5.5")
        assert get_client_ip(request) == "5.5.5.5"

    def test_xff_with_two_proxies(self, settings):
        settings.NUM_PROXIES = 2
        # XFF = "real-client, proxy1" — 2 proxies: index = max(2-2,0)=0
        request = make_request(xff="real-client, proxy1")
        assert get_client_ip(request) == "real-client"

    def test_xff_chain_shorter_than_proxies_takes_first(self, settings):
        settings.NUM_PROXIES = 5
        request = make_request(xff="only-one-ip")
        # index = max(1 - 5, 0) = 0 → first entry
        assert get_client_ip(request) == "only-one-ip"

    def test_empty_xff_falls_back_to_remote_addr(self, settings):
        settings.NUM_PROXIES = 1
        request = make_request(remote_addr="9.9.9.9", xff="")
        assert get_client_ip(request) == "9.9.9.9"

    def test_no_remote_addr_returns_empty_string(self):
        request = factory.get("/")
        request.META.pop("REMOTE_ADDR", None)
        result = get_client_ip(request)
        assert result == ""


# ── fingerprint_for_request ───────────────────────────────────────────────────


class TestFingerprintForRequest:
    def test_returns_64_char_hex_string(self):
        request = make_request()
        fp = fingerprint_for_request(request)
        assert isinstance(fp, str)
        assert len(fp) == 64
        int(fp, 16)  # must be valid hex

    def test_same_inputs_produce_same_fingerprint(self):
        r1 = make_request(remote_addr="1.1.1.1", user_agent="UA/1")
        r2 = make_request(remote_addr="1.1.1.1", user_agent="UA/1")
        assert fingerprint_for_request(r1) == fingerprint_for_request(r2)

    def test_different_ip_produces_different_fingerprint(self):
        r1 = make_request(remote_addr="1.1.1.1", user_agent="UA/1")
        r2 = make_request(remote_addr="2.2.2.2", user_agent="UA/1")
        assert fingerprint_for_request(r1) != fingerprint_for_request(r2)

    def test_different_user_agent_produces_different_fingerprint(self):
        r1 = make_request(remote_addr="1.1.1.1", user_agent="Chrome/1")
        r2 = make_request(remote_addr="1.1.1.1", user_agent="Firefox/1")
        assert fingerprint_for_request(r1) != fingerprint_for_request(r2)

    def test_fingerprint_matches_manual_sha256(self):
        request = make_request(remote_addr="3.3.3.3", user_agent="Bot/1.0")
        expected = hashlib.sha256(b"3.3.3.3|Bot/1.0").hexdigest()
        assert fingerprint_for_request(request) == expected

    def test_missing_user_agent_does_not_raise(self):
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "1.2.3.4"
        # No HTTP_USER_AGENT set
        fp = fingerprint_for_request(request)
        assert len(fp) == 64

"""v1.4 subdomain-hardening tests — SD-2 (exchange origin allowlist),
SD-3 (fingerprint-bound redemption), SD-1/SD-5 (cookie-config warnings)."""

import warnings
from contextlib import contextmanager
from typing import Any

import pytest
from django.conf import settings as dj_settings
from django.test import override_settings

from tokenforge.apps import TokenForgeConfig
from tokenforge.services.exchange import ExchangeTokenService
from tokenforge.settings import reload_settings


@contextmanager
def tf_settings(**overrides: Any):
    merged = {**getattr(dj_settings, "TOKENFORGE", {}), **overrides}
    cm = override_settings(TOKENFORGE=merged)
    cm.enable()
    reload_settings()
    try:
        yield
    finally:
        cm.disable()
        reload_settings()


# ── SD-2 — exchange target-origin allowlist ───────────────────────────────────


class TestExchangeOriginAllowlist:
    def test_disallowed_origin_rejected(self) -> None:
        with (
            tf_settings(EXCHANGE_ALLOWED_ORIGINS=["https://app.example.com"]),
            pytest.raises(ValueError),
        ):
            ExchangeTokenService.create(
                user_id="u", device_session_id="s", target_origin="https://evil.com"
            )

    def test_allowed_origin_accepted(self) -> None:
        with tf_settings(EXCHANGE_ALLOWED_ORIGINS=["https://app.example.com"]):
            token = ExchangeTokenService.create(
                user_id="u", device_session_id="s", target_origin="https://app.example.com"
            )
            assert isinstance(token, str)

    def test_unset_allowlist_refused(self) -> None:
        # 2.0 is fail-closed: an unset allowlist refuses creation outright.
        with tf_settings(EXCHANGE_ALLOWED_ORIGINS=None), pytest.raises(ValueError):
            ExchangeTokenService.create(
                user_id="u", device_session_id="s", target_origin="https://app.example.com"
            )


# ── SD-3 — fingerprint-bound exchange redemption ──────────────────────────────

_ORIGIN = "https://app.example.com"


class TestExchangeFingerprintBinding:
    def _make(self, fp: str) -> str:
        return ExchangeTokenService.create(
            user_id="u", device_session_id="s", fingerprint=fp, target_origin=_ORIGIN
        )

    def test_mismatch_rejected_when_strict(self) -> None:
        with tf_settings(EXCHANGE_ALLOWED_ORIGINS=[_ORIGIN], EXCHANGE_FINGERPRINT_STRICT=True):
            token = self._make("a" * 16)
            with pytest.raises(ValueError):
                ExchangeTokenService.redeem(
                    token=token, request_origin=_ORIGIN, request_fingerprint="b" * 16
                )

    def test_mismatch_allowed_when_soft(self) -> None:
        with tf_settings(EXCHANGE_ALLOWED_ORIGINS=[_ORIGIN], EXCHANGE_FINGERPRINT_STRICT=False):
            token = self._make("a" * 16)
            payload = ExchangeTokenService.redeem(
                token=token, request_origin=_ORIGIN, request_fingerprint="b" * 16
            )
            assert payload["sub"] == "u"

    def test_match_accepted_when_strict(self) -> None:
        with tf_settings(EXCHANGE_ALLOWED_ORIGINS=[_ORIGIN], EXCHANGE_FINGERPRINT_STRICT=True):
            token = self._make("a" * 16)
            # Stored fp is a 16-char prefix; the request fingerprint is the full hash.
            payload = ExchangeTokenService.redeem(
                token=token, request_origin=_ORIGIN, request_fingerprint="a" * 16 + "tail"
            )
            assert payload["sub"] == "u"


# ── SD-1 / SD-5 — cookie-config safety warnings ───────────────────────────────


class TestCookieConfigWarnings:
    def test_domain_wide_cookie_warns(self) -> None:
        with tf_settings(REFRESH_TOKEN_COOKIE_DOMAIN=".example.com"), pytest.warns(UserWarning):
            TokenForgeConfig._warn_unsafe_cookie_config()

    def test_root_path_warns(self) -> None:
        with tf_settings(REFRESH_TOKEN_COOKIE_PATH="/"), pytest.warns(UserWarning):
            TokenForgeConfig._warn_unsafe_cookie_config()

    def test_domain_and_root_path_is_hard_error(self) -> None:
        # SD-5 (2.0): the broadest combo — domain-wide AND path='/' — is refused.
        from django.core.exceptions import ImproperlyConfigured

        with (
            tf_settings(REFRESH_TOKEN_COOKIE_DOMAIN=".example.com", REFRESH_TOKEN_COOKIE_PATH="/"),
            pytest.raises(ImproperlyConfigured),
        ):
            TokenForgeConfig._warn_unsafe_cookie_config()

    def test_safe_config_does_not_warn(self) -> None:
        with (
            tf_settings(
                REFRESH_TOKEN_COOKIE_DOMAIN=None,
                REFRESH_TOKEN_COOKIE_PATH="/api/v1/auth/token/refresh/",
            ),
            warnings.catch_warnings(),
        ):
            warnings.simplefilter("error")  # any warning becomes an error
            TokenForgeConfig._warn_unsafe_cookie_config()

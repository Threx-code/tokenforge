"""
Tests for tokenforge.cookies — set_refresh_cookie and expire_refresh_cookie.
"""

from rest_framework.response import Response

from tokenforge.cookies import expire_refresh_cookie, set_refresh_cookie


def make_response():
    """Return a minimal DRF Response."""
    r = Response()
    # DRF Response needs to be rendered before accessing cookies.
    # We can call set_cookie/delete_cookie directly without rendering.
    return r


# ── set_refresh_cookie ────────────────────────────────────────────────────────


class TestSetRefreshCookie:
    def test_cookie_is_set_with_correct_name(self):
        response = make_response()
        set_refresh_cookie(response, "my-raw-token")
        assert "refresh_token" in response.cookies

    def test_cookie_value_equals_raw_token(self):
        response = make_response()
        set_refresh_cookie(response, "my-raw-token-value")
        assert response.cookies["refresh_token"].value == "my-raw-token-value"

    def test_cookie_is_httponly(self):
        response = make_response()
        set_refresh_cookie(response, "tok")
        assert response.cookies["refresh_token"]["httponly"] is True

    def test_cookie_secure_flag_matches_settings(self, settings):
        settings.TOKENFORGE = {
            **settings.TOKENFORGE,
            "REFRESH_TOKEN_COOKIE_SECURE": False,
        }
        from tokenforge.settings import reload_settings

        reload_settings()
        response = make_response()
        set_refresh_cookie(response, "tok")
        # When SECURE=False the flag should not be set
        assert not response.cookies["refresh_token"]["secure"]
        # Restore
        reload_settings()

    def test_cookie_max_age_is_positive(self):
        response = make_response()
        set_refresh_cookie(response, "tok")
        max_age = response.cookies["refresh_token"]["max-age"]
        assert int(max_age) > 0

    def test_cookie_max_age_reflects_lifetime_days(self, settings):
        settings.TOKENFORGE = {
            **settings.TOKENFORGE,
            "REFRESH_TOKEN_LIFETIME_DAYS": 7,
        }
        from tokenforge.settings import reload_settings

        reload_settings()
        response = make_response()
        set_refresh_cookie(response, "tok")
        assert response.cookies["refresh_token"]["max-age"] == 7 * 86400
        # Restore
        settings.TOKENFORGE = {
            **settings.TOKENFORGE,
            "REFRESH_TOKEN_LIFETIME_DAYS": 30,
        }
        reload_settings()

    def test_cookie_path_is_set(self):
        response = make_response()
        set_refresh_cookie(response, "tok")
        # Default path from settings
        path = response.cookies["refresh_token"]["path"]
        assert isinstance(path, str)
        assert len(path) > 0

    def test_cookie_samesite_is_set(self):
        response = make_response()
        set_refresh_cookie(response, "tok")
        samesite = response.cookies["refresh_token"]["samesite"]
        assert samesite in ("Lax", "Strict", "None")


# ── expire_refresh_cookie ─────────────────────────────────────────────────────


class TestExpireRefreshCookie:
    def test_cookie_name_is_set(self):
        response = make_response()
        expire_refresh_cookie(response)
        assert "refresh_token" in response.cookies

    def test_cookie_value_is_empty_string(self):
        response = make_response()
        expire_refresh_cookie(response)
        assert response.cookies["refresh_token"].value == ""

    def test_cookie_max_age_is_zero(self):
        response = make_response()
        expire_refresh_cookie(response)
        assert response.cookies["refresh_token"]["max-age"] == 0

    def test_cookie_is_httponly(self):
        response = make_response()
        expire_refresh_cookie(response)
        assert response.cookies["refresh_token"]["httponly"] is True

    def test_expire_after_set_clears_value(self):
        response = make_response()
        set_refresh_cookie(response, "live-token")
        expire_refresh_cookie(response)
        # After expiry, value should be empty
        assert response.cookies["refresh_token"].value == ""
        assert response.cookies["refresh_token"]["max-age"] == 0

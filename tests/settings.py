"""
Minimal Django settings for running django-tokenforge tests.

Uses SQLite in-memory for all runs (no external DB required).

Override with environment variables:
  REDIS_URL  — Redis connection string (defaults to LocMemCache)
"""

import os

SECRET_KEY = "insecure-test-secret-key-do-not-use-in-production"

DEBUG = True

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "rest_framework",
    "tokenforge",
]

# ── Database ──────────────────────────────────────────────────────────────────
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# ── Cache ─────────────────────────────────────────────────────────────────────
REDIS_URL = os.environ.get("REDIS_URL", "")
if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_URL,
        }
    }
else:
    # Use fakeredis for unit tests so Redis is not required
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    }

# ── TokenForge ────────────────────────────────────────────────────────────────
TOKENFORGE = {
    "ACCESS_TOKEN_SIGNING_KEY": "test-signing-key-not-for-production-use",
    "REFRESH_TOKEN_COOKIE_SECURE": False,
    "USER_CACHE_TTL": 0,  # Disable caching in tests for predictable behaviour
}
TOKENFORGE_TOKEN_MODEL = "tokenforge.RefreshToken"

# ── DRF ──────────────────────────────────────────────────────────────────────
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "tokenforge.authentication.BearerTokenAuthentication",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "refresh_token": "1000/minute",
        "request_rate": "1000/minute",
    },
}

# ── URLs ──────────────────────────────────────────────────────────────────────
ROOT_URLCONF = "tests.urls"

# ── Misc ──────────────────────────────────────────────────────────────────────
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

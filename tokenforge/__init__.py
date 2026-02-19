"""
django-tokenforge — Stateless Bearer token authentication for Django REST Framework.

Features:
  - HMAC-SHA256 signed access tokens (no DB hit per request)
  - Refresh tokens with rotation and replay detection
  - One-time exchange tokens for cross-subdomain auth (via Redis)
  - Configurable callbacks for risk events, device validation, and user serialization
  - Swappable token model (like AUTH_USER_MODEL)

Quick start:
  1. Add "tokenforge" to INSTALLED_APPS
  2. Add TOKENFORGE = {...} to settings
  3. Add path("auth/", include("tokenforge.urls")) to urls
  4. Set REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] = ["tokenforge.authentication.BearerTokenAuthentication"]
"""

__version__ = "1.0.0"
default_app_config = "tokenforge.apps.TokenForgeConfig"

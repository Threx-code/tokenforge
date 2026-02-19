"""
URL configuration for the test suite.

Mounts tokenforge URLs at the standard path so view tests can use
hardcoded URLs like /api/v1/auth/token/refresh/.
"""

from django.urls import include, path

urlpatterns = [
    path("api/v1/auth/", include("tokenforge.urls")),
]

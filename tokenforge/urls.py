"""
TokenForge URL patterns.

Usage:
    path("api/v1/auth/", include("tokenforge.urls")),
"""

from django.urls import path

from tokenforge.api.views import (
    ExchangeCreateView,
    ExchangeRedeemView,
    LogoutAllView,
    LogoutView,
    MobileTokenRefreshView,
    TokenRefreshView,
)

app_name = "tokenforge"

urlpatterns = [
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("mobile/token/refresh/", MobileTokenRefreshView.as_view(), name="mobile-token-refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("logout-all/", LogoutAllView.as_view(), name="logout-all"),
    path("exchange/create/", ExchangeCreateView.as_view(), name="exchange-create"),
    path("exchange/redeem/", ExchangeRedeemView.as_view(), name="exchange-redeem"),
]

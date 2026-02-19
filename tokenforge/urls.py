"""
TokenForge URL patterns.

Usage:
    path("api/v1/auth/", include("tokenforge.urls")),
"""

from django.urls import path

from tokenforge.views import ExchangeCreateView, ExchangeRedeemView, TokenRefreshView

app_name = "tokenforge"

urlpatterns = [
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("exchange/create/", ExchangeCreateView.as_view(), name="exchange-create"),
    path("exchange/redeem/", ExchangeRedeemView.as_view(), name="exchange-redeem"),
]

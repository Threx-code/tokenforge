"""
TokenForge serializers — request validation for exchange token views.
"""

from rest_framework import serializers


class ExchangeCreateSerializer(serializers.Serializer):  # type: ignore[type-arg]
    target_origin = serializers.URLField(required=True)


class ExchangeRedeemSerializer(serializers.Serializer):  # type: ignore[type-arg]
    exchange_token = serializers.CharField(required=True, max_length=256)

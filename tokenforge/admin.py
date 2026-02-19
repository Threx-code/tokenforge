"""
TokenForge admin — RefreshToken admin registration.
"""

from django.contrib import admin

from tokenforge.models import get_token_model

try:
    TokenModel = get_token_model()

    @admin.register(TokenModel)
    class RefreshTokenAdmin(admin.ModelAdmin):  # type: ignore[type-arg]
        list_display = ["user", "token_family", "revoked", "expires_at", "created_at"]
        list_filter = ["revoked"]
        search_fields = ["user__email", "token_family"]
        readonly_fields = ["token_family", "fingerprint", "created_at"]
        exclude = ["token_hash"]  # Never expose hash in admin
        ordering = ["-created_at"]
except LookupError:
    # TOKEN_MODEL not installed yet (e.g., during migrations)
    pass

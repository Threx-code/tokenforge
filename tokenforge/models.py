"""
TokenForge models — Abstract + Concrete refresh token with swappable support.

The AbstractRefreshToken provides all core fields for token lifecycle
management. Projects can inherit it and add custom fields (e.g., device_session FK).

To swap the model:
    TOKENFORGE = {"TOKEN_MODEL": "myapp.MyRefreshToken"}
"""

import uuid
from typing import Any

from django.apps import apps
from django.conf import settings
from django.db import models
from django.utils import timezone


class AbstractRefreshToken(models.Model):
    """
    Abstract base model for refresh tokens.

    Inherit this in your app and add project-specific fields:
        class MyRefreshToken(AbstractRefreshToken):
            device_session = ForeignKey("myapp.DeviceSession", ...)
            class Meta(AbstractRefreshToken.Meta):
                db_table = "my_refresh_tokens"
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="%(app_label)s_refresh_tokens",
    )
    token_hash = models.CharField(
        max_length=128,
        unique=True,
        db_index=True,
        help_text="SHA-256 hex digest of the raw token.",
    )
    token_family = models.UUIDField(
        default=uuid.uuid4,
        db_index=True,
        help_text="Groups all rotated descendants. Used for replay detection.",
    )
    fingerprint = models.CharField(
        max_length=256,
        blank=True,
        help_text="SHA-256(IP|UA) at issuance time.",
    )
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    replaced_by = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="replaces",
        help_text="Points to the token that replaced this one on rotation.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=["user", "revoked"]),
            models.Index(fields=["token_family"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self) -> str:
        status = "revoked" if self.revoked else "active"
        return f"RefreshToken(user={self.user_id}, {status}, family={self.token_family})"

    @property
    def is_expired(self) -> bool:
        return bool(timezone.now() >= self.expires_at)

    @property
    def is_usable(self) -> bool:
        return not self.revoked and not self.is_expired


class RefreshToken(AbstractRefreshToken):
    """
    Default concrete refresh token model.

    Override by setting TOKENFORGE["TOKEN_MODEL"] = "myapp.MyRefreshToken".
    When overridden, this model's migration is a no-op.
    """

    class Meta(AbstractRefreshToken.Meta):
        app_label = "tokenforge"
        db_table = "tokenforge_refresh_tokens"
        swappable = "TOKENFORGE_TOKEN_MODEL"


def get_token_model() -> type[Any]:
    """
    Resolve the active refresh token model from settings.

    Similar to django.contrib.auth.get_user_model().
    """
    from tokenforge.settings import tokenforge_settings

    model_path: Any = tokenforge_settings.TOKEN_MODEL
    try:
        return apps.get_model(model_path)
    except (LookupError, ValueError) as e:
        raise LookupError(
            f"TokenForge: TOKEN_MODEL '{model_path}' is not installed or not a valid model. "
            f"Ensure the app is in INSTALLED_APPS and the model exists."
        ) from e

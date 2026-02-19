from django.apps import AppConfig


class TokenForgeConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "tokenforge"
    verbose_name = "TokenForge Authentication"

    def ready(self) -> None:
        import tokenforge.signals  # noqa: F401 — register signal definitions

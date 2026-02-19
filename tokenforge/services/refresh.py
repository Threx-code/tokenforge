"""
Refresh Token Service — create, rotate, revoke with replay detection.

Token lifecycle:
  1. create_refresh_token() — first login, returns raw token + model
  2. rotate_refresh_token() — exchange old token for new one
  3. revoke_by_family()     — revoke ALL tokens in a family (replay detected)
  4. revoke_all_for_user()  — full logout across all devices

Security:
  - Only SHA-256 hash stored in DB; raw token sent once in Set-Cookie
  - Token family groups rotated descendants for replay detection
  - If a revoked token is reused -> entire family compromised -> revoke all
  - Fingerprint binding validates device consistency
"""

import contextlib
import hashlib
import logging
import secrets
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone

from tokenforge.models import get_token_model
from tokenforge.signals import replay_detected, token_revoked, token_rotated

logger = logging.getLogger("tokenforge")


def _hash_token(raw_token: str) -> str:
    """SHA-256 hex digest of a raw token string."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _generate_raw_token() -> str:
    """Generate a cryptographically secure random token."""
    from tokenforge.settings import tokenforge_settings

    nbytes = tokenforge_settings.REFRESH_TOKEN_BYTES
    return secrets.token_urlsafe(nbytes)


def _get_lifetime() -> timedelta:
    from tokenforge.settings import tokenforge_settings

    return timedelta(days=tokenforge_settings.REFRESH_TOKEN_LIFETIME_DAYS)


def _get_risk_event_handler() -> Callable[..., Any] | None:
    """Get the optional risk event handler callback."""
    from tokenforge.settings import tokenforge_settings

    val = tokenforge_settings.RISK_EVENT_HANDLER
    return val if callable(val) else None


def _get_device_validator() -> Callable[..., Any] | None:
    """Get the optional device session validator callback."""
    from tokenforge.settings import tokenforge_settings

    val = tokenforge_settings.DEVICE_SESSION_VALIDATOR
    return val if callable(val) else None


# ─────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────


def create_refresh_token(
    *,
    user: Any,
    device_session: Any = None,
    fingerprint: str = "",
    token_family: uuid.UUID | None = None,
) -> tuple[str, Any]:
    """
    Create a new refresh token for a user.

    Args:
        user: The authenticated user.
        device_session: Optional device session instance.
        fingerprint: SHA-256(IP|UA) at issuance time.
        token_family: UUID grouping rotated tokens. None = new family.

    Returns:
        (raw_token, RefreshToken instance)
    """
    TokenModel = get_token_model()
    raw_token = _generate_raw_token()
    token_hash = _hash_token(raw_token)
    family = token_family or uuid.uuid4()

    kwargs = {
        "user": user,
        "token_hash": token_hash,
        "token_family": family,
        "fingerprint": fingerprint,
        "expires_at": timezone.now() + _get_lifetime(),
    }

    # Only set device_session if the model has that field
    if device_session is not None and hasattr(TokenModel, "device_session"):
        kwargs["device_session"] = device_session

    instance = TokenModel.objects.create(**kwargs)

    logger.info(
        "Refresh token created: user=%s, family=%s, session=%s",
        user.id,
        family,
        getattr(device_session, "id", None),
    )

    return raw_token, instance


@transaction.atomic
def rotate_refresh_token(
    *,
    raw_token: str,
    fingerprint: str = "",
    request: Any = None,
) -> tuple[str, Any]:
    """
    Rotate a refresh token: validate old -> create new -> mark old as replaced.

    Returns:
        (new_raw_token, new_RefreshToken_instance)

    Raises:
        ValueError: On any validation failure.
    """
    from tokenforge.settings import tokenforge_settings

    TokenModel = get_token_model()
    token_hash = _hash_token(raw_token)

    # Look up by hash — select_for_update prevents concurrent rotation
    try:
        old_token = (
            TokenModel.objects.select_for_update(of=("self",))
            .select_related("user")
            .get(token_hash=token_hash)
        )
    except TokenModel.DoesNotExist as e:
        raise ValueError("Invalid refresh token") from e

    # Replay detection
    if old_token.revoked:
        if tokenforge_settings.REPLAY_DETECTION_ENABLED:
            logger.warning(
                "REPLAY DETECTED: revoked refresh token reused. user=%s, family=%s, token_id=%s",
                old_token.user_id,
                old_token.token_family,
                old_token.id,
            )
            _revoke_family(
                old_token.token_family,
                reason="replay_detection",
                user=old_token.user,
                request=request,
            )
        raise ValueError("Token replay detected")

    # Expiry check
    if old_token.is_expired:
        old_token.revoked = True
        old_token.revoked_at = timezone.now()
        old_token.save(update_fields=["revoked", "revoked_at"])
        raise ValueError("Refresh token expired")

    # Device session validation (via configurable callback)
    device_session = getattr(old_token, "device_session", None)
    validator = _get_device_validator()
    if validator and device_session:
        try:
            validator(device_session)
        except Exception as e:
            logger.warning("Device session validation failed: %s", str(e))
            raise ValueError(str(e)) from e
    elif device_session:
        # Default validation if no custom validator
        if getattr(device_session, "revoked", False):
            raise ValueError("Device session revoked")

        risk_threshold = tokenforge_settings.RISK_SCORE_THRESHOLD
        if getattr(device_session, "risk_score", 0) >= risk_threshold:
            raise ValueError("Session risk score too high")

        bot_threshold = tokenforge_settings.BOT_SCORE_THRESHOLD
        if getattr(device_session, "bot_score", 0) >= bot_threshold:
            raise ValueError("Automated request detected")

    # Fingerprint drift check (soft)
    if fingerprint and old_token.fingerprint and fingerprint != old_token.fingerprint:
        logger.warning(
            "Fingerprint drift on token rotation: user=%s",
            old_token.user_id,
        )
        risk_handler = _get_risk_event_handler()
        if risk_handler and request:
            with contextlib.suppress(Exception):  # Risk logging should never block auth
                risk_handler(
                    event_type="fingerprint_drift",
                    severity=30,
                    user=old_token.user,
                    device_session=device_session,
                    request=request,
                    fingerprint=fingerprint,
                    risk_score=getattr(device_session, "risk_score", 0) if device_session else 0,
                    bot_score=getattr(device_session, "bot_score", 0) if device_session else 0,
                )

    # Rotate: create new, revoke old
    new_raw_token, new_instance = create_refresh_token(
        user=old_token.user,
        device_session=device_session,
        fingerprint=fingerprint or old_token.fingerprint,
        token_family=old_token.token_family,
    )

    old_token.revoked = True
    old_token.revoked_at = timezone.now()
    old_token.replaced_by = new_instance
    old_token.save(update_fields=["revoked", "revoked_at", "replaced_by"])

    logger.info(
        "Refresh token rotated: user=%s, family=%s, old=%s -> new=%s",
        old_token.user_id,
        old_token.token_family,
        old_token.pk,
        new_instance.pk,
    )

    # Fire signal
    token_rotated.send(
        sender=type(new_instance),
        user=old_token.user,
        request=request,
    )

    return new_raw_token, new_instance


def revoke_by_family(token_family: uuid.UUID, *, reason: str = "manual") -> int:
    """Revoke ALL refresh tokens in a family. Returns count revoked."""
    TokenModel = get_token_model()
    now = timezone.now()
    count = TokenModel.objects.filter(
        token_family=token_family,
        revoked=False,
    ).update(revoked=True, revoked_at=now)

    logger.info("Revoked %d tokens in family %s (reason: %s)", count, token_family, reason)

    token_revoked.send(
        sender=TokenModel,
        family=token_family,
        count=count,
        reason=reason,
    )

    return int(count)


def revoke_all_for_user(user: Any) -> int:
    """Revoke ALL refresh tokens for a user (full logout). Returns count revoked."""
    TokenModel = get_token_model()
    now = timezone.now()
    count = TokenModel.objects.filter(
        user=user,
        revoked=False,
    ).update(revoked=True, revoked_at=now)

    logger.info("Revoked all %d refresh tokens for user %s", count, user.id)
    return int(count)


def revoke_by_device_session(device_session: Any) -> int:
    """Revoke all refresh tokens tied to a specific device session. Returns count revoked."""
    TokenModel = get_token_model()
    if not hasattr(TokenModel, "device_session"):
        return 0

    now = timezone.now()
    count = TokenModel.objects.filter(
        device_session=device_session,
        revoked=False,
    ).update(revoked=True, revoked_at=now)

    logger.info("Revoked %d refresh tokens for device session %s", count, device_session.id)
    return int(count)


def get_active_token_for_session(device_session: Any) -> Any:
    """Get the active (non-revoked, non-expired) refresh token for a device session."""
    TokenModel = get_token_model()
    if not hasattr(TokenModel, "device_session"):
        return None

    return (
        TokenModel.objects.filter(
            device_session=device_session,
            revoked=False,
            expires_at__gt=timezone.now(),
        )
        .order_by("-created_at")
        .first()
    )


def cleanup_expired_tokens(*, older_than_days: int = 90) -> int:
    """Delete expired and revoked tokens older than N days. For periodic cleanup."""
    TokenModel = get_token_model()
    cutoff = timezone.now() - timedelta(days=older_than_days)
    count, _ = TokenModel.objects.filter(
        revoked=True,
        revoked_at__lt=cutoff,
    ).delete()

    logger.info("Cleaned up %d expired refresh tokens (older than %d days)", count, older_than_days)
    return int(count)


# ─────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────


def _revoke_family(
    token_family: uuid.UUID,
    *,
    reason: str,
    user: Any = None,
    request: Any = None,
) -> None:
    """Revoke entire family + fire signal + optional risk event."""
    count = revoke_by_family(token_family, reason=reason)

    # Fire replay signal
    TokenModel = get_token_model()
    replay_detected.send(
        sender=TokenModel,
        user=user,
        family=token_family,
        request=request,
    )

    # Optional risk event callback
    risk_handler = _get_risk_event_handler()
    if risk_handler and user and request:
        with contextlib.suppress(Exception):  # Risk logging should never block auth
            risk_handler(
                event_type="token_replay_detected",
                severity=90,
                user=user,
                request=request,
                metadata={
                    "token_family": str(token_family),
                    "tokens_revoked": count,
                    "reason": reason,
                },
            )

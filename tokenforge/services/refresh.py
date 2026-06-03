"""
Refresh Token Service — create, rotate, revoke with replay detection.

Token lifecycle:
  1. RefreshTokenService.create()          — first login, returns raw token + model
  2. RefreshTokenService.rotate()          — exchange old token for new one
  3. RefreshTokenService.revoke_by_family()— revoke ALL tokens in a family (replay)
  4. RefreshTokenService.revoke_all_for_user() — full logout across all devices

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
import warnings
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone

from tokenforge.models import get_token_model
from tokenforge.signals import TokenSignals

logger = logging.getLogger("tokenforge")


class RefreshTokenService:
    """Create, rotate, and revoke refresh tokens with replay detection.

    Stateless (all state is in the DB), so the public surface is classmethods.
    """

    # ── low-level helpers ────────────────────────────────
    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """SHA-256 hex digest of a raw token string."""
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    @staticmethod
    def _generate_raw_token() -> str:
        """Generate a cryptographically secure random token."""
        from tokenforge.settings import tokenforge_settings

        return secrets.token_urlsafe(tokenforge_settings.REFRESH_TOKEN_BYTES)

    @staticmethod
    def _lifetime() -> timedelta:
        from tokenforge.settings import tokenforge_settings

        return timedelta(days=tokenforge_settings.REFRESH_TOKEN_LIFETIME_DAYS)

    @staticmethod
    def _risk_event_handler() -> Callable[..., Any] | None:
        from tokenforge.settings import tokenforge_settings

        val = tokenforge_settings.RISK_EVENT_HANDLER
        return val if callable(val) else None

    @staticmethod
    def _device_validator() -> Callable[..., Any] | None:
        from tokenforge.settings import tokenforge_settings

        val = tokenforge_settings.DEVICE_SESSION_VALIDATOR
        return val if callable(val) else None

    # ── create ───────────────────────────────────────────
    @classmethod
    def create(
        cls,
        *,
        user: Any,
        device_session: Any = None,
        fingerprint: str = "",
        token_family: uuid.UUID | None = None,
    ) -> tuple[str, Any]:
        """Create a new refresh token for a user.

        Returns (raw_token, RefreshToken instance). ``token_family`` None = a new
        family (a login); passing one marks this a rotation (no session pruning).
        """
        TokenModel = get_token_model()
        raw_token = cls._generate_raw_token()
        token_hash = cls._hash_token(raw_token)
        family = token_family or uuid.uuid4()

        kwargs = {
            "user": user,
            "token_hash": token_hash,
            "token_family": family,
            "fingerprint": fingerprint,
            "expires_at": timezone.now() + cls._lifetime(),
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

        # New session (a login, not a rotation): enforce the per-user active cap.
        if token_family is None:
            cls._enforce_active_token_cap(user)

        return raw_token, instance

    @classmethod
    def _enforce_active_token_cap(cls, user: Any) -> None:
        """Revoke the oldest active refresh tokens beyond
        MAX_ACTIVE_REFRESH_TOKENS_PER_USER. No-op when the setting is unset."""
        from tokenforge.settings import tokenforge_settings

        cap = tokenforge_settings.MAX_ACTIVE_REFRESH_TOKENS_PER_USER
        if not cap:
            return
        TokenModel = get_token_model()
        active_ids = list(
            TokenModel.objects.filter(user=user, revoked=False, expires_at__gt=timezone.now())
            .order_by("-created_at")
            .values_list("id", flat=True)
        )
        stale = active_ids[int(cap) :]
        if stale:
            TokenModel.objects.filter(id__in=stale).update(revoked=True, revoked_at=timezone.now())
            logger.info(
                "Active-token cap: revoked %d oldest token(s) for user %s", len(stale), user.id
            )

    # ── rotate ───────────────────────────────────────────
    @classmethod
    def rotate(
        cls,
        *,
        raw_token: str,
        fingerprint: str = "",
        request: Any = None,
        strict_fingerprint: bool | None = None,
    ) -> tuple[str, Any]:
        """Rotate a refresh token: validate old -> create new -> mark old replaced.

        Returns (new_raw_token, new_RefreshToken_instance). Raises ValueError on
        any validation failure.

        Note on transactions (H4): the lock + rotation run inside
        ``transaction.atomic``, but replay handling is performed AFTER that block
        commits. Revoking the family *and then raising* inside the atomic would
        roll the revocation back, leaving a compromised family usable — the very
        thing replay detection exists to prevent.
        """
        from tokenforge.settings import tokenforge_settings

        TokenModel = get_token_model()
        token_hash = cls._hash_token(raw_token)

        # Captured inside the transaction, handled durably after it commits.
        replay_family: uuid.UUID | None = None
        replay_user: Any = None
        replay_token_id: Any = None

        with transaction.atomic():
            # Look up by hash — select_for_update serialises concurrent rotation.
            try:
                old_token = (
                    TokenModel.objects.select_for_update(of=("self",))
                    .select_related("user")
                    .get(token_hash=token_hash)
                )
            except TokenModel.DoesNotExist as e:
                raise ValueError("Invalid refresh token") from e

            if old_token.revoked:
                if cls._within_reuse_grace(old_token, fingerprint):
                    # A retry of a token we just rotated, whose replacement is
                    # still active and whose fingerprint matches → rotate the
                    # current token rather than nuking the family.
                    logger.info(
                        "Refresh reuse within grace window — rotating current token. "
                        "user=%s, family=%s",
                        old_token.user_id,
                        old_token.token_family,
                    )
                    return cls._perform_rotation(
                        old_token.replaced_by, fingerprint=fingerprint, request=request
                    )
                # Replay. Capture context and fall out of the transaction so the
                # family revocation below is durable (see the H4 note above).
                replay_family = old_token.token_family
                replay_user = old_token.user
                replay_token_id = old_token.id
            else:
                # Expiry check
                if old_token.is_expired:
                    old_token.revoked = True
                    old_token.revoked_at = timezone.now()
                    old_token.save(update_fields=["revoked", "revoked_at"])
                    raise ValueError("Refresh token expired")

                # Device session validation (via configurable callback)
                device_session = getattr(old_token, "device_session", None)
                validator = cls._device_validator()
                if validator and device_session:
                    try:
                        validator(device_session)
                    except Exception as e:
                        logger.warning("Device session validation failed: %s", str(e))
                        raise ValueError(str(e)) from e
                elif device_session:
                    cls._default_device_gate(device_session)

                # Fingerprint drift check. Always logged + risk-evented. Hard-fails
                # only when strict enforcement is on — the real device-binding
                # boundary; with it off, drift is monitoring only. Strictness
                # resolves per-call: ``strict_fingerprint`` overrides
                # FINGERPRINT_STRICT_REFRESH (lets web enforce while mobile, whose
                # IP/UA is unstable, exempts).
                strict = (
                    strict_fingerprint
                    if strict_fingerprint is not None
                    else tokenforge_settings.FINGERPRINT_STRICT_REFRESH
                )
                if fingerprint and old_token.fingerprint and fingerprint != old_token.fingerprint:
                    logger.warning(
                        "Fingerprint drift on token rotation: user=%s (strict=%s)",
                        old_token.user_id,
                        strict,
                    )
                    risk_handler = cls._risk_event_handler()
                    if risk_handler and request:
                        with contextlib.suppress(Exception):  # risk logging never blocks auth
                            risk_handler(
                                event_type="fingerprint_drift",
                                severity=30,
                                user=old_token.user,
                                device_session=device_session,
                                request=request,
                                fingerprint=fingerprint,
                                risk_score=getattr(device_session, "risk_score", 0)
                                if device_session
                                else 0,
                                bot_score=getattr(device_session, "bot_score", 0)
                                if device_session
                                else 0,
                            )
                    if strict:
                        raise ValueError("Refresh token fingerprint mismatch")

                # Rotate: create the next token in the family and revoke this one.
                return cls._perform_rotation(old_token, fingerprint=fingerprint, request=request)

        # ── Replay (only reached when replay context was captured above) ──────
        # The transaction has committed, so this revocation is durable.
        if tokenforge_settings.REPLAY_DETECTION_ENABLED and replay_family is not None:
            logger.warning(
                "REPLAY DETECTED: revoked refresh token reused. user=%s, family=%s, token_id=%s",
                getattr(replay_user, "id", None),
                replay_family,
                replay_token_id,
            )
            cls._revoke_family(
                replay_family, reason="replay_detection", user=replay_user, request=request
            )
        raise ValueError("Token replay detected")

    @classmethod
    def _default_device_gate(cls, device_session: Any) -> None:
        """Built-in device-session gating used when no DEVICE_SESSION_VALIDATOR is
        configured. Raises ValueError to reject the rotation.

        If the session model exposes none of the gate fields, the gates silently
        pass — warn (M1) so that is not a silent fail-open."""
        from tokenforge.settings import tokenforge_settings

        if not any(
            hasattr(device_session, attr) for attr in ("revoked", "risk_score", "bot_score")
        ):
            warnings.warn(
                "tokenforge: the device session exposes none of 'revoked'/'risk_score'/"
                "'bot_score', so the built-in refresh gates are no-ops. Set "
                "TOKENFORGE['DEVICE_SESSION_VALIDATOR'] for real session gating.",
                stacklevel=2,
            )
        if getattr(device_session, "revoked", False):
            raise ValueError("Device session revoked")
        if getattr(device_session, "risk_score", 0) >= tokenforge_settings.RISK_SCORE_THRESHOLD:
            raise ValueError("Session risk score too high")
        if getattr(device_session, "bot_score", 0) >= tokenforge_settings.BOT_SCORE_THRESHOLD:
            raise ValueError("Automated request detected")

    @staticmethod
    def _within_reuse_grace(old_token: Any, fingerprint: str) -> bool:
        """True if reusing this (revoked) token is a legitimate double-submit
        inside REFRESH_REUSE_GRACE_SECONDS — i.e. it was just rotated, its
        replacement is still active, and the fingerprint matches. Returns False
        (strict replay) by default, so the default path takes no extra query."""
        from tokenforge.settings import tokenforge_settings

        grace = tokenforge_settings.REFRESH_REUSE_GRACE_SECONDS
        if not grace or grace <= 0:
            return False
        replacement = getattr(old_token, "replaced_by", None)
        if replacement is None or replacement.revoked or replacement.is_expired:
            return False
        if not old_token.revoked_at:
            return False
        if (timezone.now() - old_token.revoked_at).total_seconds() > grace:
            return False
        # A drifted reuse is not a "legit" double-submit.
        return not (fingerprint and old_token.fingerprint and fingerprint != old_token.fingerprint)

    @classmethod
    def _perform_rotation(
        cls, old_token: Any, *, fingerprint: str = "", request: Any = None
    ) -> tuple[str, Any]:
        """Create the next token in the family, revoke ``old_token``, fire the
        rotation signal, and return ``(new_raw_token, new_instance)``."""
        device_session = getattr(old_token, "device_session", None)
        new_raw_token, new_instance = cls.create(
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

        TokenSignals.rotated.send(
            sender=type(new_instance),
            user=old_token.user,
            request=request,
        )

        return new_raw_token, new_instance

    # ── revoke / cleanup ─────────────────────────────────
    @classmethod
    def revoke_by_family(cls, token_family: uuid.UUID, *, reason: str = "manual") -> int:
        """Revoke ALL refresh tokens in a family. Returns count revoked."""
        TokenModel = get_token_model()
        count = TokenModel.objects.filter(token_family=token_family, revoked=False).update(
            revoked=True, revoked_at=timezone.now()
        )

        logger.info("Revoked %d tokens in family %s (reason: %s)", count, token_family, reason)

        TokenSignals.revoked.send(
            sender=TokenModel,
            family=token_family,
            count=count,
            reason=reason,
        )

        return int(count)

    @classmethod
    def revoke_by_raw_token(cls, raw_token: str, *, reason: str = "logout") -> int:
        """Revoke the token family for a raw refresh token (single-session logout).

        Returns the number of tokens revoked, or 0 if the token is unknown.
        Revoking the whole family (not just this token) ensures any in-flight
        rotated descendant is killed too.
        """
        if not raw_token:
            return 0
        TokenModel = get_token_model()
        try:
            token = TokenModel.objects.only("token_family").get(
                token_hash=cls._hash_token(raw_token)
            )
        except TokenModel.DoesNotExist:
            return 0
        return cls.revoke_by_family(token.token_family, reason=reason)

    @classmethod
    def revoke_all_for_user(cls, user: Any) -> int:
        """Revoke ALL refresh tokens for a user (full logout). Returns count revoked."""
        TokenModel = get_token_model()
        count = TokenModel.objects.filter(user=user, revoked=False).update(
            revoked=True, revoked_at=timezone.now()
        )
        logger.info("Revoked all %d refresh tokens for user %s", count, user.id)
        return int(count)

    @classmethod
    def revoke_by_device_session(cls, device_session: Any) -> int:
        """Revoke all refresh tokens tied to a device session. Returns count revoked."""
        TokenModel = get_token_model()
        if not hasattr(TokenModel, "device_session"):
            return 0

        count = TokenModel.objects.filter(device_session=device_session, revoked=False).update(
            revoked=True, revoked_at=timezone.now()
        )
        logger.info("Revoked %d refresh tokens for device session %s", count, device_session.id)
        return int(count)

    @classmethod
    def get_active_token_for_session(cls, device_session: Any) -> Any:
        """Get the active (non-revoked, non-expired) refresh token for a session."""
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

    @classmethod
    def cleanup_expired(cls, *, older_than_days: int = 90) -> int:
        """Delete revoked tokens older than N days. For periodic cleanup."""
        TokenModel = get_token_model()
        cutoff = timezone.now() - timedelta(days=older_than_days)
        count, _ = TokenModel.objects.filter(revoked=True, revoked_at__lt=cutoff).delete()
        logger.info(
            "Cleaned up %d expired refresh tokens (older than %d days)", count, older_than_days
        )
        return int(count)

    # ── internal ─────────────────────────────────────────
    @classmethod
    def _revoke_family(
        cls,
        token_family: uuid.UUID,
        *,
        reason: str,
        user: Any = None,
        request: Any = None,
    ) -> None:
        """Revoke entire family + fire signal + optional risk event."""
        count = cls.revoke_by_family(token_family, reason=reason)

        TokenModel = get_token_model()
        TokenSignals.replay_detected.send(
            sender=TokenModel,
            user=user,
            family=token_family,
            request=request,
        )

        risk_handler = cls._risk_event_handler()
        if risk_handler and user and request:
            with contextlib.suppress(Exception):  # risk logging should never block auth
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

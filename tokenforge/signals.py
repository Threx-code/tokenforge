"""
TokenForge signals — hook into token lifecycle events.

Usage:
    from tokenforge.signals import TokenSignals

    @receiver(TokenSignals.rotated)
    def on_token_rotated(sender, user, request, **kwargs):
        ...
"""

from django.dispatch import Signal


class TokenSignals:
    """Namespace of the token-lifecycle Django signals.

    Class attributes (each a ``django.dispatch.Signal``):
      rotated         — after a refresh token is successfully rotated.
                        sender=TokenModel, user=user, request=request
      revoked         — after tokens are revoked.
                        sender=TokenModel, family=uuid, count=int, reason=str
      replay_detected — when a revoked token is reused.
                        sender=TokenModel, user=user, family=uuid, request=request
    """

    rotated = Signal()
    revoked = Signal()
    replay_detected = Signal()

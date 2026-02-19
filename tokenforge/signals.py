"""
TokenForge signals — hook into token lifecycle events.

Usage:
    from tokenforge.signals import token_rotated

    @receiver(token_rotated)
    def on_token_rotated(sender, user, request, **kwargs):
        ...
"""

from django.dispatch import Signal

# Fired after a refresh token is successfully rotated
token_rotated = Signal()  # sender=TokenModel, user=user, request=request

# Fired after tokens are revoked
token_revoked = Signal()  # sender=TokenModel, family=uuid, count=int, reason=str

# Fired when replay attack is detected (revoked token reused)
replay_detected = Signal()  # sender=TokenModel, user=user, family=uuid, request=request

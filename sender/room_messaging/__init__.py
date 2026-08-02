"""Layered Matrix sender room-messaging extensions."""

from .account import SenderAccountMixin
from .delayed import SenderDelayedMixin
from .location import SenderLocationMixin
from .profile import SenderProfileMixin
from .relations import SenderRelationsMixin


class SenderRoomMessagingMixin(
    SenderAccountMixin,
    SenderRelationsMixin,
    SenderProfileMixin,
    SenderLocationMixin,
    SenderDelayedMixin,
):
    """Compose account, relation, profile, location, and delay helpers."""

    pass


__all__ = [
    "SenderRoomMessagingMixin",
    "SenderAccountMixin",
    "SenderRelationsMixin",
    "SenderProfileMixin",
    "SenderLocationMixin",
    "SenderDelayedMixin",
]

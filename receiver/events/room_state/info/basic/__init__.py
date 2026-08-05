"""Basic room metadata state-event handlers."""

from .avatar import handle_room_avatar_change
from .create import handle_room_create
from .encryption import handle_room_encryption
from .name import handle_room_name_change
from .tombstone import handle_room_tombstone
from .topic import handle_room_topic_change

__all__ = [
    "handle_room_avatar_change",
    "handle_room_create",
    "handle_room_encryption",
    "handle_room_name_change",
    "handle_room_tombstone",
    "handle_room_topic_change",
]

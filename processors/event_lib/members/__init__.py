"""Composable Matrix room member and profile processing operations."""

import asyncio  # noqa: F401

from astrbot.api import logger  # noqa: F401

from ....constants import (
    M_ROOM_LIVE_MESSAGING,
    MEMBERSHIP_BAN,
    MEMBERSHIP_INVITE,
    MEMBERSHIP_JOIN,
    MEMBERSHIP_KNOCK,
    MEMBERSHIP_LEAVE,
    MSC4357_LIVE_MESSAGING_STATE,
)  # noqa: F401
from ....storage.stores.rooms import MatrixRoomMemberStore  # noqa: F401
from ....storage.stores.users import MatrixUserStore  # noqa: F401
from .membership import MatrixEventProcessorMembershipChangesMixin
from .storage import MatrixEventProcessorMemberStorageMixin


class MatrixEventProcessorMembers(
    MatrixEventProcessorMemberStorageMixin,
    MatrixEventProcessorMembershipChangesMixin,
):
    """Mixin for membership updates and profile persistence."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MatrixEventProcessorMembers._init_member_storage = (
    MatrixEventProcessorMemberStorageMixin.__dict__["_init_member_storage"]
)
MatrixEventProcessorMembers.load_room_members_from_storage = (
    MatrixEventProcessorMemberStorageMixin.__dict__["load_room_members_from_storage"]
)
MatrixEventProcessorMembers._persist_interacted_user = (
    MatrixEventProcessorMemberStorageMixin.__dict__["_persist_interacted_user"]
)
MatrixEventProcessorMembers._handle_member_event = (
    MatrixEventProcessorMembershipChangesMixin.__dict__["_handle_member_event"]
)


__all__ = [
    "M_ROOM_LIVE_MESSAGING",
    "MEMBERSHIP_BAN",
    "MEMBERSHIP_INVITE",
    "MEMBERSHIP_JOIN",
    "MEMBERSHIP_KNOCK",
    "MEMBERSHIP_LEAVE",
    "MSC4357_LIVE_MESSAGING_STATE",
    "MatrixEventProcessorMembers",
    "MatrixRoomMemberStore",
    "MatrixUserStore",
    "asyncio",
    "logger",
]

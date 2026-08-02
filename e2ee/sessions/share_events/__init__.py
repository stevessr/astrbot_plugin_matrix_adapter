"""Composable room and device event handlers for room-key sharing."""

import time

from astrbot.api import logger

from ....constants import (
    M_ROOM_ENCRYPTION,
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_MEMBER,
    MEMBERSHIP_INVITE,
    MEMBERSHIP_JOIN,
    PREFIX_CURVE25519,
    PREFIX_ED25519,
)
from ...constants import (
    DEFAULT_HISTORY_VISIBILITY,
    DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC,
    HISTORY_VISIBILITY_INVITED,
    HISTORY_VISIBILITY_JOINED,
    INVITE_KEY_SHARE_VISIBILITIES,
    SHAREABLE_HISTORY_VISIBILITIES,
    VALID_HISTORY_VISIBILITIES,
)
from .devices import E2EEManagerSessionShareEventsDevicesMixin
from .members import E2EEManagerSessionShareEventsMembersMixin
from .membership import E2EEManagerSessionShareEventsMembershipMixin
from .visibility import E2EEManagerSessionShareEventsVisibilityMixin


class E2EEManagerSessionShareEventsMixin(
    E2EEManagerSessionShareEventsVisibilityMixin,
    E2EEManagerSessionShareEventsMembershipMixin,
    E2EEManagerSessionShareEventsDevicesMixin,
    E2EEManagerSessionShareEventsMembersMixin,
):
    """分层处理历史可见性、成员和设备列表事件。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
E2EEManagerSessionShareEventsMixin._normalize_history_visibility = staticmethod(
    E2EEManagerSessionShareEventsVisibilityMixin._normalize_history_visibility
)
E2EEManagerSessionShareEventsMixin._history_visibility_is_shareable = classmethod(
    E2EEManagerSessionShareEventsVisibilityMixin.__dict__[
        "_history_visibility_is_shareable"
    ].__func__
)

for _method_name in (
    "invalidate_room_members_cache",
    "set_room_encryption_config",
    "_get_room_history_visibility",
    "_get_room_shared_history",
    "on_history_visibility_changed",
):
    setattr(
        E2EEManagerSessionShareEventsMixin,
        _method_name,
        getattr(E2EEManagerSessionShareEventsVisibilityMixin, _method_name),
    )

for _method_name in (
    "on_room_member_joined",
    "on_room_member_invited",
    "on_room_member_left",
):
    setattr(
        E2EEManagerSessionShareEventsMixin,
        _method_name,
        getattr(E2EEManagerSessionShareEventsMembershipMixin, _method_name),
    )

for _method_name in (
    "on_device_list_changed",
    "on_device_list_left",
):
    setattr(
        E2EEManagerSessionShareEventsMixin,
        _method_name,
        getattr(E2EEManagerSessionShareEventsDevicesMixin, _method_name),
    )

E2EEManagerSessionShareEventsMixin._get_room_members = (
    E2EEManagerSessionShareEventsMembersMixin._get_room_members
)


__all__ = [
    "DEFAULT_HISTORY_VISIBILITY",
    "DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC",
    "E2EEManagerSessionShareEventsDevicesMixin",
    "E2EEManagerSessionShareEventsMembersMixin",
    "E2EEManagerSessionShareEventsMembershipMixin",
    "E2EEManagerSessionShareEventsMixin",
    "E2EEManagerSessionShareEventsVisibilityMixin",
    "HISTORY_VISIBILITY_INVITED",
    "HISTORY_VISIBILITY_JOINED",
    "INVITE_KEY_SHARE_VISIBILITIES",
    "M_ROOM_ENCRYPTION",
    "M_ROOM_HISTORY_VISIBILITY",
    "M_ROOM_MEMBER",
    "MEMBERSHIP_INVITE",
    "MEMBERSHIP_JOIN",
    "PREFIX_CURVE25519",
    "PREFIX_ED25519",
    "SHAREABLE_HISTORY_VISIBILITIES",
    "VALID_HISTORY_VISIBILITIES",
    "logger",
    "time",
]

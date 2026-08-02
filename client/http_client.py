"""
Matrix HTTP Client - Direct implementation without matrix-nio
Implements the Matrix Client-Server API using aiohttp

This module provides a modular HTTP client for Matrix, composed of:
- MatrixClientBase: Core HTTP request functionality
- MessageOverrideMixin: Overridable hooks around message send/fetch
- AuthMixin: Authentication and sync
- RoomMixin: Room operations
- MessageMixin: Message sending and manipulation
- MediaMixin: File upload and download
- ProfileMixin: User profile and presence
- DeviceMixin: Device management
- E2EEMixin: End-to-end encryption
- WidgetMixin: Widget management
- UserMixin: User management and moderation
"""

from .account_mixin import AccountMixin
from .auth_mixin import AuthMixin
from .base import MatrixAPIError, MatrixClientBase
from .delayed_events_mixin import DelayedEventsMixin
from .device_mixin import DeviceMixin
from .e2ee_mixin import E2EEMixin
from .key_backup_mixin import KeyBackupMixin
from .media import MediaMixin
from .message import MessageMixin
from .message_override_mixin import MessageOverrideMixin
from .profile import ProfileMixin
from .push_mixin import PushMixin
from .room_mixin import RoomMixin
from .tags_mixin import TagsMixin
from .thirdparty_mixin import ThirdPartyMixin
from .user import UserMixin
from .voip_mixin import VoipMixin
from .widget_mixin import WidgetMixin


class MatrixHTTPClient(
    MatrixClientBase,
    # 必须排在 RoomMixin / MessageMixin 之前，才能拦截 send_message、
    # get_event 与 room_messages，并让 super() 沿 MRO 落到真实实现上。
    MessageOverrideMixin,
    AccountMixin,
    AuthMixin,
    RoomMixin,
    MessageMixin,
    MediaMixin,
    ProfileMixin,
    DeviceMixin,
    E2EEMixin,
    KeyBackupMixin,
    PushMixin,
    TagsMixin,
    ThirdPartyMixin,
    WidgetMixin,
    UserMixin,
    VoipMixin,
    DelayedEventsMixin,
):
    """
    Complete Matrix HTTP client combining all API modules.

    This class provides a full-featured Matrix client by combining
    the base HTTP functionality with specialized mixins for different
    API categories.

    Usage:
        client = MatrixHTTPClient("https://matrix.example.com")
        await client.login_password("@user:example.com", "password")
        await client.send_room_message("!room:example.com", "Hello!")
        await client.close()
    """

    pass


# Re-export for backward compatibility
__all__ = [
    "MatrixHTTPClient",
    "MatrixAPIError",
    "MatrixClientBase",
    "AccountMixin",
    "AuthMixin",
    "RoomMixin",
    "MessageMixin",
    "MessageOverrideMixin",
    "MediaMixin",
    "ProfileMixin",
    "DeviceMixin",
    "E2EEMixin",
    "KeyBackupMixin",
    "PushMixin",
    "TagsMixin",
    "ThirdPartyMixin",
    "WidgetMixin",
    "UserMixin",
    "VoipMixin",
    "DelayedEventsMixin",
]

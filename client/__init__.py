"""
Matrix Client - Direct implementation without matrix-nio dependency

This package provides a modular Matrix HTTP client composed of:
- MatrixHTTPClient: Complete client combining all modules
- MatrixClientBase: Core HTTP request functionality
- AuthMixin: Authentication and sync
- RoomMixin: Room operations
- MessageMixin: Message sending and manipulation
- MessageOverrideMixin: Overridable hooks around message send/fetch
- MediaMixin: File upload and download
- ProfileMixin: User profile and presence
- DeviceMixin: Device management
- E2EEMixin: End-to-end encryption
- WidgetMixin: Widget management
- UserMixin: User management and moderation
"""

from .event_types import InviteEvent, MatrixEvent, RoomMessageEvent
from .http_client import (
    AccountMixin,
    AuthMixin,
    DelayedEventsMixin,
    DeviceMixin,
    E2EEMixin,
    KeyBackupMixin,
    MatrixAPIError,
    MatrixClientBase,
    MatrixHTTPClient,
    MediaMixin,
    MessageMixin,
    MessageOverrideMixin,
    ProfileMixin,
    PushMixin,
    RoomMixin,
    TagsMixin,
    ThirdPartyMixin,
    UserMixin,
    VoipMixin,
    WidgetMixin,
)

__all__ = [
    # Main client
    "MatrixHTTPClient",
    "MatrixAPIError",
    "MatrixClientBase",
    # Mixins
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
    "WidgetMixin",
    "UserMixin",
    "TagsMixin",
    "ThirdPartyMixin",
    "VoipMixin",
    "DelayedEventsMixin",
    # Event types
    "MatrixEvent",
    "RoomMessageEvent",
    "InviteEvent",
]

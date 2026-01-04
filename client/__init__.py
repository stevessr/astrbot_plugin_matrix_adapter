"""
Matrix Client - Direct implementation without matrix-nio dependency

This package provides a modular Matrix HTTP client composed of:
- MatrixHTTPClient: Complete client combining all modules
- MatrixClientBase: Core HTTP request functionality
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

from .event_types import InviteEvent, MatrixEvent, RoomMessageEvent
from .http_client import (
    AccountMixin,
    AuthMixin,
    DeviceMixin,
    E2EEMixin,
    KeyBackupMixin,
    MatrixAPIError,
    MatrixClientBase,
    MatrixHTTPClient,
    MediaMixin,
    MessageMixin,
    ProfileMixin,
    PushMixin,
    RoomMixin,
    UserMixin,
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
    "MediaMixin",
    "ProfileMixin",
    "DeviceMixin",
    "E2EEMixin",
    "KeyBackupMixin",
    "PushMixin",
    "WidgetMixin",
    "UserMixin",
    # Event types
    "MatrixEvent",
    "RoomMessageEvent",
    "InviteEvent",
]

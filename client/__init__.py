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
"""

from .event_types import InviteEvent, MatrixEvent, RoomMessageEvent
from .http_client import (
    AuthMixin,
    DeviceMixin,
    E2EEMixin,
    MatrixAPIError,
    MatrixClientBase,
    MatrixHTTPClient,
    MediaMixin,
    MessageMixin,
    ProfileMixin,
    RoomMixin,
    WidgetMixin,
)

__all__ = [
    # Main client
    "MatrixHTTPClient",
    "MatrixAPIError",
    "MatrixClientBase",
    # Mixins
    "AuthMixin",
    "RoomMixin",
    "MessageMixin",
    "MediaMixin",
    "ProfileMixin",
    "DeviceMixin",
    "E2EEMixin",
    "WidgetMixin",
    # Event types
    "MatrixEvent",
    "RoomMessageEvent",
    "InviteEvent",
]

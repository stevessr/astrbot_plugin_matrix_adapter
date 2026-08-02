"""
Matrix HTTP client package.

This package provides a modular HTTP client composed of the base client
and specialized mixins for each Matrix API category.
"""

from ..account_mixin import AccountMixin
from ..auth import AuthMixin
from ..base import MatrixAPIError, MatrixClientBase
from ..delayed_events_mixin import DelayedEventsMixin
from ..device_mixin import DeviceMixin
from ..e2ee_mixin import E2EEMixin
from ..key_backup_mixin import KeyBackupMixin
from ..media import MediaMixin
from ..message import MessageMixin
from ..message_override_mixin import MessageOverrideMixin
from ..profile import ProfileMixin
from ..push_mixin import PushMixin
from ..room_mixin import RoomMixin
from ..tags_mixin import TagsMixin
from ..thirdparty_mixin import ThirdPartyMixin
from ..user import UserMixin
from ..voip_mixin import VoipMixin
from ..widget_mixin import WidgetMixin
from .composition import MatrixHTTPClient

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

"""
Matrix HTTP Client - Room Mixin
Combines room-related API methods from sub-mixins
"""

from .room_core_mixin import RoomCoreMixin
from .room_directory_mixin import RoomDirectoryMixin
from .room_management_mixin import RoomManagementMixin
from .room_state_mixin import RoomStateMixin


class RoomMixin(
    RoomCoreMixin,
    RoomDirectoryMixin,
    RoomManagementMixin,
    RoomStateMixin,
):
    """Room-related methods for Matrix client"""

    pass

"""
Sync manager callbacks mixin
Provides the set_*_callback methods for the sync manager
"""

from collections.abc import Callable


class MatrixSyncManagerCallbacksMixin:
    """Callback setter methods for MatrixSyncManager."""

    def set_room_event_callback(self, callback: Callable):
        """
        Set callback for room events

        Args:
            callback: Async function(room_id, room_data) -> None
        """
        self.on_room_event = callback

    def set_to_device_event_callback(self, callback: Callable):
        """
        Set callback for to-device events

        Args:
            callback: Async function(events) -> None
        """
        self.on_to_device_event = callback

    def set_invite_callback(self, callback: Callable):
        """
        Set callback for invite events

        Args:
            callback: Async function(room_id, invite_data) -> None
        """
        self.on_invite = callback

    def set_knock_callback(self, callback: Callable):
        """
        Set callback for knock events (MSC2403)

        Args:
            callback: Async function(room_id, knock_data) -> None
        """
        self.on_knock = callback

    def set_leave_callback(self, callback: Callable):
        """
        Set callback for leave events

        Args:
            callback: Async function(room_id, leave_data) -> None
        """
        self.on_leave = callback

    def set_ephemeral_callback(self, callback: Callable):
        """
        Set callback for ephemeral events

        Args:
            callback: Async function(room_id, ephemeral_data) -> None
        """
        self.on_ephemeral_event = callback

    def set_room_account_data_callback(self, callback: Callable):
        """
        Set callback for room account data events

        Args:
            callback: Async function(room_id, account_data) -> None
        """
        self.on_room_account_data = callback

    def set_account_data_callback(self, callback: Callable):
        """
        Set callback for account data events

        Args:
            callback: Async function(account_data) -> None
        """
        self.on_account_data = callback

    def set_presence_callback(self, callback: Callable):
        """
        Set callback for presence events

        Args:
            callback: Async function(events) -> None
        """
        self.on_presence_event = callback

    def set_device_lists_callback(self, callback: Callable):
        """
        Set callback for device list changes

        Args:
            callback: Async function(changed, left) -> None
        """
        self.on_device_lists = callback

    def set_device_one_time_keys_count_callback(self, callback: Callable):
        """
        Set callback for one-time keys count changes

        Args:
            callback: Async function(counts) -> None
        """
        self.on_device_one_time_keys_count = callback

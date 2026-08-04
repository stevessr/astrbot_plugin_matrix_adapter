"""Sync callback wiring for adapter service composition."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any


def _wire_callbacks(
    sync_manager: Any,
    event_processor: Any,
    event_handler: Any,
    on_sync_response: Callable[[dict], Awaitable[None]] | None = None,
    message_callback: Callable[..., Awaitable[None]] | None = None,
):
    """Attach event handlers to the sync manager and processor."""
    sync_manager.set_room_event_callback(event_processor.process_room_events)
    sync_manager.set_to_device_event_callback(event_processor.process_to_device_events)
    sync_manager.set_invite_callback(event_handler.invite_callback)
    sync_manager.set_knock_callback(event_handler.knock_callback)
    sync_manager.set_leave_callback(event_processor.process_leave_events)
    sync_manager.set_ephemeral_callback(event_processor.process_ephemeral_events)
    sync_manager.set_room_account_data_callback(
        event_processor.process_room_account_data_events
    )
    sync_manager.set_account_data_callback(event_processor.process_account_data_events)
    sync_manager.set_presence_callback(event_processor.process_presence_events)
    sync_manager.set_device_lists_callback(event_processor.process_device_lists)
    sync_manager.set_device_one_time_keys_count_callback(
        event_processor.process_device_one_time_keys_count
    )
    if on_sync_response is not None:
        sync_manager.on_sync = on_sync_response
    if message_callback is not None:
        event_processor.set_message_callback(message_callback)

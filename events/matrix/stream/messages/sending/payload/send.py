"""Live message send and edit delivery."""

from .......constants import M_ROOM_MESSAGE
from .......sender.event_send.crypto import (
    edit_message_encrypted,
    edit_message_plain,
    send_message_encrypted,
    send_message_plain,
)


class MatrixPlatformEventMessagesPayloadSendMixin:
    """Send initial live messages and edits."""

    async def _send_initial_live_message(
        self,
        room_id: str,
        msg_type: str,
        content: dict,
        tracker_metadata: dict,
        is_encrypted_room: bool,
    ) -> str:
        """Send the initial live message and return its event id."""
        if is_encrypted_room:
            response = await send_message_encrypted(
                self.client,
                self.e2ee_manager,
                room_id,
                M_ROOM_MESSAGE,
                content,
                tracker_metadata=tracker_metadata,
            )
        else:
            response = await send_message_plain(
                self.client,
                room_id,
                M_ROOM_MESSAGE,
                content,
                tracker_metadata=tracker_metadata,
            )
        event_id = (response or {}).get("event_id")
        if not event_id:
            raise RuntimeError("Matrix live message initial response omitted event_id")
        return str(event_id)

    async def _edit_live_message(
        self,
        room_id: str,
        current_event_id: str,
        content: dict,
        tracker_metadata: dict,
        is_encrypted_room: bool,
        stream_thread_root,
    ) -> None:
        """Edit an existing live message in place."""
        if is_encrypted_room:
            await edit_message_encrypted(
                self.client,
                self.e2ee_manager,
                room_id,
                current_event_id,
                content,
                tracker_metadata=tracker_metadata,
                thread_root=stream_thread_root,
            )
        else:
            await edit_message_plain(
                self.client,
                room_id,
                current_event_id,
                content,
                tracker_metadata=tracker_metadata,
                thread_root=stream_thread_root,
            )


__all__ = ["MatrixPlatformEventMessagesPayloadSendMixin"]

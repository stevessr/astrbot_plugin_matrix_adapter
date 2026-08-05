"""Live message buffer append and flush."""

import time


class MatrixPlatformEventMessagesLiveFlushMixin:
    """Append text and flush the streaming buffer when due."""

    async def _append_and_flush_stream_buffer(
        self,
        *,
        buffer: str,
        text: str,
        current_event_id: str | None,
        last_sent_text: str,
        last_flush_at: float,
        flush_interval: float,
        room_id: str,
        msg_type: str,
        initial_relation,
        is_encrypted_room: bool,
        stream_thread_root,
    ):
        """Append text and send when due; return the updated state tuple."""
        buffer += text

        should_flush = current_event_id is None or (
            buffer != last_sent_text
            and (time.monotonic() - last_flush_at) >= flush_interval
        )
        if should_flush:
            (
                _,
                current_event_id,
                last_sent_text,
                last_flush_at,
            ) = await self._send_live_payload(
                buffer,
                final=False,
                room_id=room_id,
                msg_type=msg_type,
                current_event_id=current_event_id,
                last_sent_text=last_sent_text,
                last_flush_at=last_flush_at,
                initial_relation=initial_relation,
                is_encrypted_room=is_encrypted_room,
                stream_thread_root=stream_thread_root,
            )
        return buffer, current_event_id, last_sent_text, last_flush_at


__all__ = ["MatrixPlatformEventMessagesLiveFlushMixin"]

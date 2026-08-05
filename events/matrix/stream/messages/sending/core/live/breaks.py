"""Live message break-chunk handling."""

from astrbot.api.event import MessageChain


class MatrixPlatformEventMessagesLiveBreakMixin:
    """Handle break chunks in the streaming generator."""

    async def _handle_stream_break(
        self,
        *,
        buffer: str,
        current_event_id: str | None,
        last_sent_text: str,
        last_flush_at: float,
        used_self_send: bool,
        room_id: str,
        msg_type: str,
        initial_relation,
        is_encrypted_room: bool,
        stream_thread_root,
    ):
        """Finalize a pending buffer on break; return the reset state tuple."""
        if current_event_id is None:
            if buffer:
                await self.send(MessageChain().message(buffer))
                used_self_send = True
        else:
            (
                _,
                current_event_id,
                last_sent_text,
                last_flush_at,
            ) = await self._send_live_payload(
                buffer,
                final=True,
                room_id=room_id,
                msg_type=msg_type,
                current_event_id=current_event_id,
                last_sent_text=last_sent_text,
                last_flush_at=last_flush_at,
                initial_relation=initial_relation,
                is_encrypted_room=is_encrypted_room,
                stream_thread_root=stream_thread_root,
            )
        self._response_thread_context = None
        return used_self_send, "", None, "", 0.0


__all__ = ["MatrixPlatformEventMessagesLiveBreakMixin"]

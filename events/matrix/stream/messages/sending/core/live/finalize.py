"""Live message stream finalization."""

from astrbot.api.event import MessageChain


class MatrixPlatformEventMessagesLiveFinalizeMixin:
    """Finalize the streaming buffer at generator exhaustion."""

    async def _finalize_stream(
        self,
        *,
        buffer: str,
        current_event_id: str | None,
        last_sent_text: str,
        last_flush_at: float,
        used_self_send: bool,
        metric_cls,
        room_id: str,
        msg_type: str,
        initial_relation,
        is_encrypted_room: bool,
        stream_thread_root,
    ) -> None:
        """Flush the final buffer and mark the stream operation complete."""
        if current_event_id is None:
            if buffer:
                await self.send(MessageChain().message(buffer))
                used_self_send = True
            if not used_self_send:
                await self._mark_stream_operation(metric_cls)
            return

        if buffer != last_sent_text or last_sent_text:
            if buffer:
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
            else:
                await self._mark_stream_operation(metric_cls)
        await self._mark_stream_operation(metric_cls)


__all__ = ["MatrixPlatformEventMessagesLiveFinalizeMixin"]

"""Live message edit-loop state machine."""

from astrbot.api.event import MessageChain


class MatrixPlatformEventMessagesLiveOrchestratorMixin:
    """Emit streaming chunks via MSC4357 marker and ``m.replace`` edits."""

    async def _send_streaming_live(
        self,
        generator,
        *,
        room_id: str,
        msg_type: str,
        flush_interval: float,
        initial_relation,
        stream_thread_root,
        is_encrypted_room: bool,
        metric_cls,
    ) -> None:
        used_self_send = False
        buffer = ""
        current_event_id: str | None = None
        last_sent_text = ""
        last_flush_at = 0.0

        async for chain in generator:
            if not isinstance(chain, MessageChain):
                continue
            if chain.type == "break":
                (
                    used_self_send,
                    buffer,
                    current_event_id,
                    last_sent_text,
                    last_flush_at,
                ) = await self._handle_stream_break(
                    buffer=buffer,
                    current_event_id=current_event_id,
                    last_sent_text=last_sent_text,
                    last_flush_at=last_flush_at,
                    used_self_send=used_self_send,
                    room_id=room_id,
                    msg_type=msg_type,
                    initial_relation=initial_relation,
                    is_encrypted_room=is_encrypted_room,
                    stream_thread_root=stream_thread_root,
                )
                continue

            text = chain.get_plain_text()
            if not text:
                continue

            (
                buffer,
                current_event_id,
                last_sent_text,
                last_flush_at,
            ) = await self._append_and_flush_stream_buffer(
                buffer=buffer,
                text=text,
                current_event_id=current_event_id,
                last_sent_text=last_sent_text,
                last_flush_at=last_flush_at,
                flush_interval=flush_interval,
                room_id=room_id,
                msg_type=msg_type,
                initial_relation=initial_relation,
                is_encrypted_room=is_encrypted_room,
                stream_thread_root=stream_thread_root,
            )

        await self._finalize_stream(
            buffer=buffer,
            current_event_id=current_event_id,
            last_sent_text=last_sent_text,
            last_flush_at=last_flush_at,
            used_self_send=used_self_send,
            metric_cls=metric_cls,
            room_id=room_id,
            msg_type=msg_type,
            initial_relation=initial_relation,
            is_encrypted_room=is_encrypted_room,
            stream_thread_root=stream_thread_root,
        )


__all__ = ["MatrixPlatformEventMessagesLiveOrchestratorMixin"]

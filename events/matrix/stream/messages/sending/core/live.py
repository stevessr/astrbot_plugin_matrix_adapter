"""Live message edit-loop state machine."""

import time

from astrbot.api.event import MessageChain


class MatrixPlatformEventMessagesLiveMixin:
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
                buffer = ""
                current_event_id = None
                last_sent_text = ""
                last_flush_at = 0.0
                continue

            text = chain.get_plain_text()
            if not text:
                continue
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

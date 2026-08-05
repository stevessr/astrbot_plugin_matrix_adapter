"""Live message payload construction and delivery."""

import time

from astrbot.api import logger


class MatrixPlatformEventMessagesPayloadOrchestratorMixin:
    """Build and send single live-message payloads."""

    async def _send_live_payload(
        self,
        text: str,
        *,
        final: bool,
        room_id: str,
        msg_type: str,
        current_event_id: str | None,
        last_sent_text: str,
        last_flush_at: float,
        initial_relation,
        is_encrypted_room: bool,
        stream_thread_root,
    ) -> tuple[bool, str | None, str, float]:
        """Send an initial or update live payload.

        Returns (sent, event_id, sent_text, flush_at); event_id is the new
        (or unchanged) live event id and sent_text/flush_at are the updated
        streaming state, mirroring the former closure's nonlocal writes.
        """
        content = self._build_live_message_content(
            text,
            msg_type=msg_type,
            final=final,
            current_event_id=current_event_id,
            initial_relation=initial_relation,
        )
        tracker_metadata = self._build_live_tracker_metadata(final, current_event_id)

        try:
            if current_event_id is None:
                current_event_id = await self._send_initial_live_message(
                    room_id,
                    msg_type,
                    content,
                    tracker_metadata,
                    is_encrypted_room,
                )
            else:
                await self._edit_live_message(
                    room_id,
                    current_event_id,
                    content,
                    tracker_metadata,
                    is_encrypted_room,
                    stream_thread_root,
                )
        except Exception as e:
            logger.warning(f"Matrix live message update failed: {e}")
            return False, current_event_id, last_sent_text, last_flush_at

        return True, current_event_id, text, time.monotonic()


__all__ = ["MatrixPlatformEventMessagesPayloadOrchestratorMixin"]

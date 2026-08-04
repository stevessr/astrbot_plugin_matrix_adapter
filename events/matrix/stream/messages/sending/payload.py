"""Live message payload construction and delivery."""

import html
import time

from astrbot.api import logger

from ......constants import (
    M_ROOM_MESSAGE,
    MATRIX_HTML_FORMAT,
    MSC4357_LIVE_MESSAGE_MARKER,
)
from ......sender.event_send.crypto import (
    edit_message_encrypted,
    edit_message_plain,
    send_message_encrypted,
    send_message_plain,
)
from ......utils.markdown_utils import markdown_to_html


class MatrixPlatformEventMessagesPayloadMixin:
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
        content = {
            "msgtype": msg_type,
            "body": text,
        }
        try:
            formatted_body = markdown_to_html(text)
        except Exception as e:
            logger.warning(f"Failed to render live message markdown: {e}")
            formatted_body = html.escape(text).replace("\n", "<br>")
        if formatted_body:
            content["format"] = MATRIX_HTML_FORMAT
            content["formatted_body"] = formatted_body
        if not final:
            content[MSC4357_LIVE_MESSAGE_MARKER] = {}
        if current_event_id is None and initial_relation:
            content["m.relates_to"] = dict(initial_relation)

        tracker_metadata = {
            "proposal": "msc4357-live-messages",
            "live_message": True,
            "phase": "final"
            if final
            else ("initial" if current_event_id is None else "edit"),
        }

        try:
            if current_event_id is None:
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
                    raise RuntimeError(
                        "Matrix live message initial response omitted event_id"
                    )
                current_event_id = str(event_id)
            else:
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
        except Exception as e:
            logger.warning(f"Matrix live message update failed: {e}")
            return False, current_event_id, last_sent_text, last_flush_at

        return True, current_event_id, text, time.monotonic()

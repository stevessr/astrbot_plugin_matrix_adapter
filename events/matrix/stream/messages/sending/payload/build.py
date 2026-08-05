"""Live message payload construction."""

import html

from astrbot.api import logger

from .......constants import (
    MATRIX_HTML_FORMAT,
    MSC4357_LIVE_MESSAGE_MARKER,
)
from .......utils.markdown_utils import markdown_to_html


class MatrixPlatformEventMessagesPayloadBuildMixin:
    """Build live-message content payloads."""

    def _build_live_message_content(
        self,
        text: str,
        *,
        msg_type: str,
        final: bool,
        current_event_id: str | None,
        initial_relation,
    ) -> dict:
        """Build the content payload for an initial or update live message."""
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
        return content


__all__ = ["MatrixPlatformEventMessagesPayloadBuildMixin"]

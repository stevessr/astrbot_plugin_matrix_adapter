"""Reaction target lookup and summary operations."""

from astrbot.api import logger

from ....constants import (
    M_REACTION,
    M_ROOM_ENCRYPTED,
    M_ROOM_MESSAGE,
    M_ROOM_REDACTION,
    MSGTYPE_AUDIO,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_STICKER,
    MSGTYPE_VIDEO,
)
from ..archive import _find_stalk_archive_message, _normalize_text


class MatrixAdapterMessageReactionMixin:
    """Resolve human-readable summaries for reaction targets."""

    async def _resolve_reaction_target_summary(self, room, event_id: str) -> str:
        if not event_id or not self.client:
            return ""
        try:
            event = await self.client.get_event(room.room_id, event_id)
        except Exception as e:
            logger.debug(f"获取 reaction 目标事件失败：{e}")
            event = None

        if event:
            sender_id = event.get("sender", "") or ""
            sender_name = room.members.get(sender_id, sender_id) if sender_id else ""
            event_type = event.get("type") or event.get("event_type") or ""
            content = event.get("content") or {}

            body = ""
            if event_type == M_ROOM_MESSAGE:
                msgtype = content.get("msgtype") or ""
                body = content.get("body") or ""
                if not body and msgtype in (
                    MSGTYPE_IMAGE,
                    MSGTYPE_VIDEO,
                    MSGTYPE_AUDIO,
                    MSGTYPE_FILE,
                ):
                    body = msgtype
                if msgtype == MSGTYPE_STICKER and not body:
                    body = "sticker"
            elif event_type == M_REACTION:
                reaction = content.get("m.relates_to", {}).get("key", "")
                body = f"[reaction] {reaction}".strip()
            elif event_type == M_ROOM_ENCRYPTED:
                body = "[encrypted]"
            elif event_type == M_ROOM_REDACTION:
                body = "[redaction]"
            else:
                body = (
                    content.get("body")
                    or content.get("name")
                    or content.get("topic")
                    or ""
                )

            body = _normalize_text(body)
            if sender_name and sender_id:
                sender = f"{sender_name}/{sender_id}"
            else:
                sender = sender_name or sender_id

            if sender and body:
                return f"{sender}: {body}"
            if sender:
                return sender
            if body:
                return body
            if event_type:
                return event_type

        return _find_stalk_archive_message(room.room_id, event_id)

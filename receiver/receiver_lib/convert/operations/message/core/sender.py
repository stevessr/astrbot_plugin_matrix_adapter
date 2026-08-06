"""Message sender construction for message conversion."""

from astrbot.api import logger
from astrbot.core.platform.astrbot_message import MessageMember


class MatrixReceiverMessageConvertSenderMixin:
    """Build sender members for converted messages."""

    def _build_message_sender(self, event, room) -> MessageMember:
        """Construct the sending user's MessageMember."""
        sender_id = getattr(event, "sender", None)
        if not isinstance(sender_id, str) or not sender_id:
            logger.warning(
                f"消息事件缺少 sender，使用占位发送者：event_id={getattr(event, 'event_id', '<unknown>')}"
            )
            sender_id = ""
        sender_name = room.members.get(sender_id, sender_id)

        return MessageMember(
            user_id=sender_id,
            nickname=sender_name,
        )


__all__ = ["MatrixReceiverMessageConvertSenderMixin"]
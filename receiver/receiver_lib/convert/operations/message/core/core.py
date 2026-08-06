"""Matrix message event conversion orchestrator."""

from astrbot.api.event import MessageChain
from astrbot.api.platform import AstrBotMessage

from .......client.event_types import MatrixRoom
from .......constants import MSGTYPE_REDACTION
from .......utils.utils import MatrixUtils

from .parse import MatrixReceiverMessageConvertParseMixin
from .sender import MatrixReceiverMessageConvertSenderMixin
from .type import MatrixReceiverMessageConvertTypeMixin


class MatrixReceiverMessageConvertOrchestratorMixin:
    """Convert Matrix message events to AstrBot messages."""

    async def convert_message(self, room: MatrixRoom, event) -> AstrBotMessage:
        """
        将 Matrix 消息转换为 AstrBot 消息格式
        """
        message = AstrBotMessage()

        # 基础信息
        message.raw_message = event

        event_content = event.content if isinstance(event.content, dict) else {}
        reply_event_id = self._parse_reply_event_id(event_content)

        # A leading Markdown blockquote is ordinary message content unless the
        # event explicitly declares a reply or thread relation.
        message.message_str = (
            MatrixUtils.strip_reply_fallback(event.body)
            if reply_event_id
            else (event.body or "")
        )
        message.session_id = room.room_id
        message.message_id = event.event_id  # Set message ID for replies
        message.self_id = self.user_id  # Set bot's self ID

        self._assign_message_type(message, room)

        # 发送者信息
        message.sender = self._build_message_sender(event, room)

        # 构建消息链
        chain = MessageChain()

        # 处理回复
        if reply_event_id:
            await self._append_reply_components(
                chain, event, event_content, reply_event_id, room
            )

        # 处理消息内容
        msgtype = event.content.get("msgtype") or getattr(event, "msgtype", None)
        event_type = getattr(event, "event_type", None)

        await self._append_message_content(chain, event, msgtype, event_type)

        if msgtype == MSGTYPE_REDACTION:
            message.message_str = "".join(
                str(getattr(component, "text", ""))
                for component in chain.chain
                if getattr(component, "text", None)
            )

        message.message = (
            chain.chain
        )  # AstrBotMessage 需要列表格式的消息链 (list[BaseMessageComponent])
        return message


__all__ = ["MatrixReceiverMessageConvertOrchestratorMixin"]
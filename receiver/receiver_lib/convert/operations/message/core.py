"""Matrix message event conversion orchestrator."""

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.platform import AstrBotMessage
from astrbot.core.platform.astrbot_message import MessageMember
from astrbot.core.platform.message_type import MessageType

from ......client.event_types import MatrixRoom
from ......config.plugin import get_plugin_config
from ......constants import MSGTYPE_REDACTION, REL_TYPE_THREAD
from ......utils.utils import MatrixUtils


class MatrixReceiverMessageConvertCoreMixin:
    """Convert Matrix message events to AstrBot messages."""

    async def convert_message(self, room: MatrixRoom, event) -> AstrBotMessage:
        """
        将 Matrix 消息转换为 AstrBot 消息格式
        """
        message = AstrBotMessage()

        # 基础信息
        message.raw_message = event

        event_content = event.content if isinstance(event.content, dict) else {}
        relates_to = event_content.get("m.relates_to", {})
        reply_event_id = None
        if isinstance(relates_to, dict):
            in_reply_to = relates_to.get("m.in_reply_to")
            if isinstance(in_reply_to, dict):
                reply_event_id = in_reply_to.get("event_id")
            if not reply_event_id and relates_to.get("rel_type") == REL_TYPE_THREAD:
                reply_event_id = relates_to.get("event_id")

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

        # 根据房间成员数量判断是否为群聊
        # is_group 属性：member_count > 2 则为群聊，否则为私聊
        # 根据配置强制消息类型，默认为 auto（按房间成员判断）
        force_type = get_plugin_config().force_message_type
        is_auto_type = force_type in {"auto", "stalk"}
        is_private = force_type == "private" or (is_auto_type and not room.is_group)
        if is_private:
            message.type = MessageType.FRIEND_MESSAGE
            logger.debug(
                "消息类型：FRIEND_MESSAGE "
                f"(force_type={force_type}, is_group={room.is_group})"
            )
        else:
            message.type = MessageType.GROUP_MESSAGE
            # 设置 group 以支持白名单的 group_id 匹配
            from astrbot.core.platform.astrbot_message import Group

            message.group = Group(group_id=room.room_id)
            logger.debug(
                "消息类型：GROUP_MESSAGE "
                f"(force_type={force_type}, is_group={room.is_group})"
            )

        # 发送者信息
        sender_id = getattr(event, "sender", None)
        if not isinstance(sender_id, str) or not sender_id:
            logger.warning(
                f"消息事件缺少 sender，使用占位发送者：event_id={getattr(event, 'event_id', '<unknown>')}"
            )
            sender_id = ""
        sender_name = room.members.get(sender_id, sender_id)

        message.sender = MessageMember(
            user_id=sender_id,
            nickname=sender_name,
        )

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

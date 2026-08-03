"""Matrix system event conversion."""

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.platform import AstrBotMessage
from astrbot.core.platform.astrbot_message import MessageMember
from astrbot.core.platform.message_type import MessageType

from .....client.event_types import MatrixRoom
from .....config.plugin import get_plugin_config
from ....events import ROOM_STATE_HANDLERS, handle_call_event, is_call_event_type


class MatrixReceiverSystemConvertMixin:
    """Convert Matrix state and call events."""

    async def convert_system_event(self, room: MatrixRoom, event) -> AstrBotMessage:
        """
        将 Matrix 非消息事件转换为 AstrBot 消息格式（OtherMessage）
        """
        message = AstrBotMessage()
        message.raw_message = event
        message.session_id = room.room_id
        message.message_id = event.event_id
        message.self_id = self.user_id
        message.type = MessageType.OTHER_MESSAGE

        force_type = get_plugin_config().force_message_type
        if force_type == "group" or (force_type in {"auto", "stalk"} and room.is_group):
            from astrbot.core.platform.astrbot_message import Group

            message.group = Group(group_id=room.room_id)

        sender_id = getattr(event, "sender", None)
        if not isinstance(sender_id, str) or not sender_id:
            logger.warning(
                f"系统事件缺少 sender，使用占位发送者：event_id={getattr(event, 'event_id', '<unknown>')}"
            )
            sender_id = ""
        sender_name = room.members.get(sender_id, sender_id)
        message.sender = MessageMember(
            user_id=sender_id,
            nickname=sender_name,
        )

        # Build message chain for state events
        chain = MessageChain()
        event_type = getattr(event, "event_type", None)

        # Resolve a handler: room state events, then VoIP / MatrixRTC call events
        handler = None
        if event_type and event_type in ROOM_STATE_HANDLERS:
            handler = ROOM_STATE_HANDLERS[event_type]
        elif event_type and is_call_event_type(event_type):
            handler = handle_call_event

        if handler is not None:
            await handler(self, chain, event, event_type)
            if chain.chain and chain.chain[0] is not None:
                first_comp = chain.chain[0]
                message.message_str = getattr(first_comp, "text", "")
            else:
                message.message_str = ""
        else:
            message.message_str = ""

        message.message = chain.chain if chain.chain else []
        return message

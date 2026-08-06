"""Message type assignment for message conversion."""

from astrbot.api import logger
from astrbot.core.platform.message_type import MessageType

from .......config.plugin import get_plugin_config


class MatrixReceiverMessageConvertTypeMixin:
    """Assign friend/group message types."""

    def _assign_message_type(self, message, room) -> None:
        """Set message.type (and group for group messages) from force config."""
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


__all__ = ["MatrixReceiverMessageConvertTypeMixin"]

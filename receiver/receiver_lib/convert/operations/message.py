"""Matrix message event conversion."""

import asyncio

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.platform import AstrBotMessage
from astrbot.core.platform.astrbot_message import MessageMember
from astrbot.core.platform.message_type import MessageType

from .....client.event_types import MatrixRoom
from .....config.plugin import get_plugin_config
from .....constants import (
    M_POLL_END,
    M_POLL_RESPONSE,
    M_POLL_START,
    MSC3381_POLL_END,
    MSC3381_POLL_RESPONSE,
    MSC3381_POLL_START,
    MSGTYPE_AUDIO,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_REDACTION,
    MSGTYPE_TEXT,
    MSGTYPE_VIDEO,
    REL_TYPE_THREAD,
)
from .....utils.utils import MatrixUtils
from ....events import (
    BEACON_EVENT_TYPES,
    handle_beacon,
    handle_beacon_info,
    handle_extensible_event,
    handle_poll_end,
    handle_poll_response,
    handle_poll_start,
    handle_unknown,
)
from .helpers import _has_extensible_content


class MatrixReceiverMessageConvertMixin:
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
            # 创建回复组件
            from astrbot.api.message_components import Reply

            # 注意：Reply 组件通常需要完整的消息对象，但这里我们只有 ID
            # AstrBot 的 Reply 组件结构可能需要适配
            reply_comp = Reply(id=reply_event_id)
            chain.chain.append(reply_comp)

            # 尝试获取引用消息中的图片
            if self.client:
                try:
                    original_event = await asyncio.wait_for(
                        self.client.get_event(room.room_id, reply_event_id),
                        timeout=self._REPLY_EVENT_FETCH_TIMEOUT_SECONDS,
                    )
                    if original_event:
                        original_content = original_event.get("content", {})
                        original_msgtype = original_content.get("msgtype")

                        if original_msgtype in {
                            MSGTYPE_IMAGE,
                            MSGTYPE_VIDEO,
                            MSGTYPE_AUDIO,
                            MSGTYPE_FILE,
                        }:
                            rendered = await self._append_quoted_media_component(
                                chain, original_msgtype, original_content
                            )
                            if rendered:
                                logger.debug(
                                    f"Added quoted media to chain: msgtype={original_msgtype}"
                                )
                except asyncio.TimeoutError:
                    logger.debug(
                        f"Reply event fetch timed out: room={room.room_id} event={reply_event_id}"
                    )
                except Exception as e:
                    logger.debug(f"Could not fetch original event for reply: {e}")

        # 处理消息内容
        msgtype = event.content.get("msgtype") or getattr(event, "msgtype", None)
        event_type = getattr(event, "event_type", None)

        # Handle poll events by event type rather than msgtype
        if event_type in (M_POLL_START, MSC3381_POLL_START):
            await handle_poll_start(self, chain, event, event_type)
        elif event_type in (M_POLL_RESPONSE, MSC3381_POLL_RESPONSE):
            await handle_poll_response(self, chain, event, event_type)
        elif event_type in (M_POLL_END, MSC3381_POLL_END):
            await handle_poll_end(self, chain, event, event_type)
        elif (
            event_type in BEACON_EVENT_TYPES
            and event_type
            and "beacon_info" in event_type
        ):
            await handle_beacon_info(self, chain, event, event_type)
        elif event_type in BEACON_EVENT_TYPES:
            await handle_beacon(self, chain, event, event_type)
        else:
            handler = self._MSGTYPE_HANDLERS.get(msgtype)
            if handler is not None:
                await handler(self, chain, event, msgtype)
            elif msgtype or not _has_extensible_content(event.content):
                await handle_unknown(self, chain, event, msgtype or "")
            else:
                await handle_extensible_event(self, chain, event, MSGTYPE_TEXT)

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

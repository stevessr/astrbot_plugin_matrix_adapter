"""Reply and quoted-media component building."""

import asyncio

from astrbot.api import logger

from ......constants import (
    MSGTYPE_AUDIO,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_VIDEO,
)


class MatrixReceiverMessageReplyMixin:
    """Append reply components and quoted media to a message chain."""

    async def _append_reply_components(
        self, chain, event, event_content, reply_event_id, room
    ):
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

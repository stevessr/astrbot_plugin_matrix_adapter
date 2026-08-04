"""Reply-target extraction and fallback resolution."""

import time

from astrbot.api import logger
from astrbot.api.message_components import Reply as _Reply

from ......constants import (
    M_ROOM_MESSAGE,
    MSGTYPE_NOTICE,
    MSGTYPE_TEXT,
)


class MatrixPlatformEventSendReplyMixin:
    """Resolve the reply target for a message chain."""

    def _extract_reply_target(self, message_chain) -> tuple[str | None, bool]:
        """Extract a Reply segment from the chain.

        Returns (reply_to, has_reply_component).
        """
        reply_to = None
        has_reply_component = False
        # 尝试从消息链中提取 Reply 段
        try:
            has_reply_component = any(
                isinstance(seg, _Reply) for seg in message_chain.chain
            )
            for seg in message_chain.chain:
                if isinstance(seg, _Reply) and getattr(seg, "id", None):
                    reply_to = str(seg.id)
                    break
        except Exception:
            logger.debug("提取 Reply 组件失败")
        return reply_to, has_reply_component

    async def _find_reply_fallback(
        self, room_id: str, has_reply_component: bool
    ) -> str | None:
        """Look up the most recent own message as a reply target.

        Returns the event id to reply to, or None when unavailable or
        throttled.
        """
        reply_to = None
        try:
            if has_reply_component:
                # 直接使用已缓存的 user_id（登录时已设置），无需额外 API 调用
                my_user_id = getattr(self.client, "user_id", None)

                if my_user_id:
                    # 节流：每房间每 5 秒最多一次回退查找
                    now = time.time()
                    last_lookup = getattr(self, "_reply_fallback_cache", {}).get(
                        room_id, 0
                    )
                    if now - last_lookup < 5.0:
                        pass  # 跳过
                    else:
                        try:
                            # 获取房间最近的消息
                            messages_resp = await self.client.room_messages(
                                room_id=room_id,
                                direction="b",  # 向后获取（最新的消息）
                                limit=50,  # 获取最近 50 条消息
                            )

                            # 查找自己最近发送的消息
                            chunk = messages_resp.get("chunk", [])
                            for event in chunk:
                                if (
                                    event.get("type") == M_ROOM_MESSAGE
                                    and event.get("sender") == my_user_id
                                    and event.get("content", {}).get("msgtype")
                                    in (MSGTYPE_TEXT, MSGTYPE_NOTICE)
                                ):
                                    reply_to = event.get("event_id")
                                    logger.debug(
                                        f"找到自己最近的消息作为回复对象：{reply_to}"
                                    )
                                    break
                        except Exception as e:
                            logger.debug(f"获取自己最近消息失败：{e}")
                        finally:
                            if not hasattr(self, "_reply_fallback_cache"):
                                self._reply_fallback_cache = {}
                            self._reply_fallback_cache[room_id] = now
        except Exception as e:
            logger.debug(f"处理回复模式时出错：{e}")
        return reply_to

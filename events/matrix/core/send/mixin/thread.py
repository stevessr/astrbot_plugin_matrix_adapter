"""Thread-target resolution for reply events."""

from astrbot.api import logger


class MatrixPlatformEventSendThreadMixin:
    """Resolve whether a reply must be threaded and its thread root."""

    async def _resolve_thread_target(
        self, room_id: str, reply_to: str
    ) -> tuple[str | None, bool, dict | None]:
        """Resolve thread context for a reply target.

        Returns (thread_root, use_thread, original_message_info).
        """
        thread_root = None
        use_thread = False
        original_message_info = None
        try:
            # 配置开启线程时，即使事件查询失败，也可以先按当前回复
            # 目标创建线程；如果查询到的目标本身已在其他线程中，下面
            # 再用真实线程根覆盖这个默认值。
            if self.enable_threading:
                use_thread = True
                thread_root = reply_to

            # 获取被回复消息的事件信息
            resp = await self.client.get_event(room_id, reply_to)
            if resp:
                # 提取原始消息信息用于 fallback
                original_message_info = {
                    "sender": resp.get("sender", ""),
                    "body": resp.get("content", {}).get("body", ""),
                    "mentions": resp.get("content", {}).get("m.mentions", {}),
                }

                # 检查被回复消息是否已经是嘟文串的一部分
                if "content" in resp:
                    relates_to = resp["content"].get("m.relates_to", {})
                    if not isinstance(relates_to, dict):
                        relates_to = {}
                    if relates_to.get("rel_type") == "m.thread":
                        # 如果是嘟文串的一部分，获取根消息 ID
                        thread_root = relates_to.get("event_id") or reply_to
                        use_thread = True
                    elif self.enable_threading:
                        # 试验性功能：如果启用嘟文串模式，创建新的嘟文串
                        use_thread = True
                        thread_root = reply_to  # 将被回复的消息作为嘟文串根
                    else:
                        # 如果不是嘟文串，不要强制开启嘟文串模式，使用标准回复
                        use_thread = False
                        thread_root = None
        except Exception as e:
            logger.warning(f"Failed to get event for threading: {e}")
        return thread_root, use_thread, original_message_info

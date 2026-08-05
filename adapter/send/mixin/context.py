"""Reply and thread context resolution for session sends."""

from astrbot.api import logger
from astrbot.api.message_components import Reply


class MatrixAdapterSendContextMixin:
    """Resolve reply target, thread root, and original message info."""

    async def _resolve_reply_context(
        self,
        message_chain,
        reply_to: str | None,
        room_id: str,
    ) -> tuple[str | None, str | None, bool, dict | None]:
        thread_root = None
        use_thread = False
        original_message_info = None

        if reply_to is None:
            try:
                for seg in message_chain.chain:
                    if isinstance(seg, Reply) and getattr(seg, "id", None):
                        reply_to = str(seg.id)
                        break
            except Exception:
                pass

        if reply_to:
            try:
                resp = await self.client.get_event(room_id, reply_to)
                if resp:
                    original_message_info = {
                        "sender": resp.get("sender", ""),
                        "body": resp.get("content", {}).get("body", ""),
                        "mentions": resp.get("content", {}).get("m.mentions", {}),
                    }

                    if "content" in resp:
                        relates_to = resp["content"].get("m.relates_to", {})
                        if relates_to.get("rel_type") == "m.thread":
                            thread_root = relates_to.get("event_id")
                            use_thread = True
                        else:
                            use_thread = (
                                self._matrix_config.enable_threading
                                if hasattr(self._matrix_config, "enable_threading")
                                else False
                            )
                            if use_thread:
                                thread_root = reply_to
            except Exception as e:
                logger.warning(f"获取事件用于嘟文串失败：{e}")

        return reply_to, thread_root, use_thread, original_message_info

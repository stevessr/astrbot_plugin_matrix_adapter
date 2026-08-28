"""Matrix message reactions and redactions."""

from astrbot.api import logger


class MatrixPlatformEventActionsMixin:
    """Apply reactions and redact event messages."""

    async def react(self, emoji: str):
        """对消息添加表情回应。"""
        try:
            event_id = getattr(self.message_obj, "message_id", None)
            if not event_id and hasattr(self.message_obj, "raw_message"):
                event_id = getattr(self.message_obj.raw_message, "event_id", None)
            if not event_id:
                logger.debug("无法添加反应：缺少 event_id")
                return
            await self.client.send_reaction(self.matrix_room_id, event_id, emoji)
        except Exception as e:
            logger.debug(f"发送表情反应失败：{e}")

    async def delete(self, reason: str | None = None, event_id: str | None = None):
        """删除（撤回）消息。"""
        try:
            target_event_id = event_id or getattr(self.message_obj, "message_id", None)
            if not target_event_id and hasattr(self.message_obj, "raw_message"):
                target_event_id = getattr(
                    self.message_obj.raw_message, "event_id", None
                )
            if not target_event_id:
                logger.warning("无法删除消息：缺少 event_id")
                return
            await self.client.redact_event(
                self.matrix_room_id, str(target_event_id), reason=reason
            )
        except Exception as e:
            logger.error(f"删除消息失败：{e}")

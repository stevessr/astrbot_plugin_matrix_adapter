"""Typing indicator helpers for session sends."""

from astrbot.api import logger

from ....constants import DEFAULT_TYPING_TIMEOUT_MS


class MatrixAdapterSendTypingMixin:
    """Start and stop typing notifications."""

    async def _start_typing(self, room_id: str) -> None:
        try:
            await self.client.set_typing(
                room_id, typing=True, timeout=DEFAULT_TYPING_TIMEOUT_MS
            )
        except Exception as e:
            logger.debug(f"发送输入通知失败：{e}")

    async def _stop_typing(self, room_id: str) -> None:
        try:
            await self.client.set_typing(room_id, typing=False)
        except Exception as e:
            logger.debug(f"停止输入通知失败：{e}")

"""Typing indicators for Matrix streaming responses."""

import asyncio

from astrbot.api import logger


class MatrixPlatformEventTypingMixin:
    """Manage typing notifications during Matrix request handling."""

    async def _typing_keepalive(self, room_id: str) -> None:
        """流式生成期间周期性续期 typing 状态，直到任务被取消。

        Matrix 的 typing 状态会在 ``timeout`` 后自动过期，而流式回复通常远长于
        此，只声明一次会让指示器中途消失，因此需要在过期前重新声明。
        """

        while True:
            await asyncio.sleep(
                self._stream_event_module().STREAMING_TYPING_REFRESH_SECONDS
            )
            try:
                await self.client.set_typing(
                    room_id,
                    typing=True,
                    timeout=self._stream_event_module().STREAMING_TYPING_TIMEOUT_MS,
                )
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.debug(f"刷新输入通知失败：{e}")

    async def send_typing(self) -> None:
        """Handle AstrBot's pre-request typing lifecycle hook."""

        if not self._send_typing_enabled:
            return
        await self.client.set_typing(
            self.session_id,
            typing=True,
            timeout=self._stream_event_module().STREAMING_TYPING_TIMEOUT_MS,
        )

    async def stop_typing(self) -> None:
        """Handle AstrBot's post-request typing lifecycle hook."""

        if not self._send_typing_enabled:
            return
        await self.client.set_typing(self.session_id, typing=False)

    async def _start_typing_keepalive(self, room_id: str):
        """按插件开关声明 typing 并启动续期任务；关闭时返回 ``None``。"""

        if not self._send_typing_enabled:
            return None
        # 先直接声明一次，保证指示器立刻出现，不依赖任务调度时机
        # （极短的流可能在续期任务首次运行前就结束了）。
        try:
            await self.client.set_typing(
                room_id,
                typing=True,
                timeout=self._stream_event_module().STREAMING_TYPING_TIMEOUT_MS,
            )
        except Exception as e:
            logger.debug(f"发送输入通知失败：{e}")
        try:
            return asyncio.create_task(self._typing_keepalive(room_id))
        except Exception as e:
            logger.debug(f"启动输入通知任务失败：{e}")
            return None

    async def _stop_typing_keepalive(self, task, room_id: str) -> None:
        """停止保活任务并显式清除 typing 状态。"""

        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"停止输入通知任务失败：{e}")
        try:
            await self.client.set_typing(room_id, typing=False)
        except Exception as e:
            logger.debug(f"停止输入通知失败：{e}")

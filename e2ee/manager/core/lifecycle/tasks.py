import asyncio

from astrbot.api import logger


class E2EEManagerCoreLifecycleTasksMixin:
    async def _start_key_share_check_task(self):
        """
        启动定期密钥分发检查任务
        """
        if self._key_share_check_task and not self._key_share_check_task.done():
            return

        async def _check_loop():
            while self._initialized:
                try:
                    await self._proactive_check_key_sharing()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.warning(f"Periodic room-key distribution check failed: {e}")
                if not self._initialized:
                    break
                try:
                    await asyncio.sleep(self.key_share_check_interval)
                except asyncio.CancelledError:
                    break

        self._key_share_check_task = asyncio.create_task(
            _check_loop(),
            name="matrix-key-share-check",
        )
        self._key_share_check_task.add_done_callback(
            self._handle_key_share_check_task_done
        )

    def _handle_key_share_check_task_done(self, task: asyncio.Task) -> None:
        if self._key_share_check_task is task:
            self._key_share_check_task = None
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"定期密钥分发检查任务异常退出：{e}")

    def stop_key_share_check_task(self) -> asyncio.Task | None:
        """停止定期密钥分发检查任务"""
        task = self._key_share_check_task
        if task and not task.done():
            task.cancel()
            logger.debug("已停止定期密钥分发检查任务")
        self._key_share_check_task = None
        return task

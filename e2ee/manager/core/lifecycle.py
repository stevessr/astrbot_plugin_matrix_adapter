"""Runtime task lifecycle and resource cleanup for the E2EE manager."""

import asyncio

from astrbot.api import logger

from .compat import vodozemac_available


class E2EEManagerCoreLifecycleMixin:
    """管理定期密钥分发任务和 E2EE 运行时资源生命周期。"""

    @property
    def is_available(self) -> bool:
        """检查 E2EE 是否可用"""
        return vodozemac_available()

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

    async def close(self) -> None:
        """Release runtime resources and flush pending persistence jobs."""
        self._closing = True
        self._initialized = False
        key_share_task = self.stop_key_share_check_task()
        if key_share_task and not key_share_task.done():
            try:
                await key_share_task
            except asyncio.CancelledError:
                pass
        store = self._store
        self._store = None
        self._olm = None
        self._verification = None
        self._key_backup = None
        self._cross_signing = None
        self._pending_room_key_requests.clear()
        self._room_key_share_locks.clear()
        self._room_encryption_config.clear()
        self._no_olm_withheld_sent.clear()
        self._olm_recovery_attempts.clear()
        self._room_key_withheld.clear()
        if store is not None and hasattr(store, "close"):
            try:
                await asyncio.to_thread(store.close)
            except Exception as e:
                logger.warning(f"E2EE store close failed: {e}")

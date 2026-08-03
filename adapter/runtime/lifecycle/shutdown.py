"""Matrix adapter shutdown and resource cleanup operations."""

import asyncio

from astrbot.api import logger


class MatrixAdapterRuntimeShutdownMixin:
    """Stop and clean up the Matrix adapter runtime."""

    async def terminate(self):
        try:
            logger.info("正在关闭 Matrix 适配器...")
            if getattr(self, "runtime_state", None):
                self.runtime_state.mark_lifecycle("stopping")
                self.runtime_state.mark_sync_stopped()

            try:
                await self.client.set_presence("offline")
                if getattr(self, "runtime_state", None):
                    self.runtime_state.mark_presence_updated()
            except Exception as e:
                logger.debug(f"设置离线状态失败：{e}")

            # 停止定期密钥分发检查任务
            key_share_check_task = None
            if hasattr(self, "e2ee_manager") and self.e2ee_manager:
                if hasattr(self.e2ee_manager, "stop_key_share_check_task"):
                    key_share_check_task = self.e2ee_manager.stop_key_share_check_task()
            if key_share_check_task and not key_share_check_task.done():
                try:
                    await key_share_check_task
                except asyncio.CancelledError:
                    pass

            if hasattr(self, "sync_manager"):
                stop_and_wait = getattr(self.sync_manager, "stop_and_wait", None)
                if callable(stop_and_wait):
                    await stop_and_wait()
                else:
                    self.sync_manager.stop()

            if (
                hasattr(self, "e2ee_manager")
                and self.e2ee_manager
                and hasattr(self.e2ee_manager, "close")
            ):
                await self.e2ee_manager.close()

            if hasattr(self, "receiver") and hasattr(self.receiver, "shutdown"):
                await self.receiver.shutdown()

            if hasattr(self, "_media_cache_gc_task") and self._media_cache_gc_task:
                self._media_cache_gc_task.cancel()
                try:
                    await self._media_cache_gc_task
                except asyncio.CancelledError:
                    pass
                self._media_cache_gc_task = None

            if self.client:
                await self.client.close()

            if getattr(self, "runtime_state", None):
                self.runtime_state.mark_lifecycle("stopped")
            logger.info("Matrix 适配器已被优雅地关闭")
        except Exception as e:
            if getattr(self, "runtime_state", None):
                self.runtime_state.record_error("terminate", str(e))
                self.runtime_state.mark_lifecycle("error")
            logger.error(f"Matrix 适配器关闭时出错：{e}")

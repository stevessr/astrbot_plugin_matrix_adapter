"""Adapter media-cache maintenance tasks."""

import asyncio

from astrbot.api import logger


class MatrixAdapterRuntimeMediaCacheMixin:
    """Run periodic media cache cleanup and task handling."""

    _MEDIA_CACHE_GC_INTERVAL_SECONDS = 6 * 60 * 60

    async def _media_cache_gc_loop(self):
        try:
            while True:
                await asyncio.sleep(self._MEDIA_CACHE_GC_INTERVAL_SECONDS)
                try:
                    removed = self.receiver.gc_media_cache()
                    if removed > 0:
                        logger.info(f"定期清理了 {removed} 个媒体缓存文件")
                except Exception as e:
                    logger.debug(f"定期媒体缓存清理失败：{e}")
        except asyncio.CancelledError:
            raise

    def _handle_media_cache_gc_task_done(self, task: asyncio.Task) -> None:
        if getattr(self, "_media_cache_gc_task", None) is task:
            self._media_cache_gc_task = None
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"媒体缓存清理任务异常退出：{e}")

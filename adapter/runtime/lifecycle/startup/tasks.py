"""Media cache GC stage of the Matrix adapter startup."""

import asyncio

from astrbot.api import logger


async def _startup_cache_gc(self) -> None:
    try:
        removed = self.receiver.gc_media_cache()
        if removed > 0:
            logger.info(f"清理了 {removed} 个媒体缓存文件")
    except Exception as e:
        logger.debug(f"媒体缓存清理失败：{e}")

    if not hasattr(self, "_media_cache_gc_task") or (
        self._media_cache_gc_task and self._media_cache_gc_task.done()
    ):
        self._media_cache_gc_task = asyncio.create_task(self._media_cache_gc_loop())
        self._media_cache_gc_task.add_done_callback(
            self._handle_media_cache_gc_task_done
        )

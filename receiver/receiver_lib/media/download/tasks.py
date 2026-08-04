"""Asyncio task deduplication and background-task tracking primitives."""

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path

from astrbot.api import logger


class MatrixReceiverMediaTasksMixin:
    """Deduplicate concurrent downloads and track fire-and-forget tasks."""

    async def _run_download_task(
        self, task_key: str, task_factory: Callable[[], Awaitable[Path]]
    ) -> Path:
        existing_task = self._media_download_tasks.get(task_key)
        if existing_task:
            return await existing_task

        task = asyncio.create_task(task_factory())
        self._media_download_tasks[task_key] = task
        try:
            return await task
        finally:
            current_task = self._media_download_tasks.get(task_key)
            if current_task is task:
                self._media_download_tasks.pop(task_key, None)

    def _track_background_task(self, task: asyncio.Task, task_name: str) -> None:
        self._background_tasks.add(task)

        def _cleanup(done_task: asyncio.Task) -> None:
            self._background_tasks.discard(done_task)
            try:
                done_task.result()
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.debug(f"Background task failed ({task_name}): {e}")

        task.add_done_callback(_cleanup)

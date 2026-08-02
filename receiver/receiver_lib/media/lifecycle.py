"""Lifecycle management for receiver media tasks."""

import asyncio


class MatrixReceiverMediaLifecycleMixin:
    """Cancel and clean up pending media tasks during shutdown."""

    async def shutdown(self) -> None:
        tasks: list[asyncio.Task] = []
        seen: set[int] = set()

        for task in list(self._background_tasks):
            if task.done():
                continue
            marker = id(task)
            if marker not in seen:
                seen.add(marker)
                tasks.append(task)

        for task in list(self._media_download_tasks.values()):
            if task.done():
                continue
            marker = id(task)
            if marker not in seen:
                seen.add(marker)
                tasks.append(task)

        for task in tasks:
            task.cancel()

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        self._background_tasks.clear()
        self._media_download_tasks.clear()

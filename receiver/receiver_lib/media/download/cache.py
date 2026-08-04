"""Atomic cache-file writes with media index updates."""

import asyncio
import time
from pathlib import Path


class MatrixReceiverMediaCacheMixin:
    """Write downloaded bytes into the receiver media cache atomically."""

    async def _write_cache_file(self, cache_path: Path, data: bytes) -> None:
        def _write() -> None:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            temp_name = f".{cache_path.name}.{time.time_ns()}.tmp"
            temp_path = cache_path.with_name(temp_name)
            temp_path.write_bytes(data)
            temp_path.replace(cache_path)

        await asyncio.to_thread(_write)
        cache_key = self._extract_cache_key_from_path(cache_path)
        if cache_key:
            self._upsert_media_cache_index_entry(
                cache_key, cache_path, size_bytes=len(data)
            )

"""JSON fallback persistence for sync tokens."""

import asyncio
import json
from pathlib import Path

from astrbot.api import logger

from ...storage.paths import MatrixStoragePaths


class SyncTokenFallbackMixin:
    def _load_sync_token_from_file(self) -> str | None:
        if not self.sync_store_path:
            return None

        try:
            path = Path(self.sync_store_path)
            if path.exists():
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                    self._next_batch = data.get("next_batch")
                    if self._next_batch:
                        logger.info("恢复同步令牌（JSON 回退）")
                        self._migrate_to_backend(data)
                    return self._next_batch
        except Exception as e:
            logger.warning(f"加载同步令牌失败（JSON 回退）：{e}")

        return None

    @staticmethod
    def _write_sync_token_file(sync_path: Path, payload: dict) -> None:
        with open(sync_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    async def _save_sync_token_to_file(self, payload: dict, now: float) -> bool:
        if not self.sync_store_path:
            return False

        try:
            sync_path = Path(self.sync_store_path)
            await asyncio.to_thread(
                MatrixStoragePaths.ensure_directory,
                sync_path,
                treat_as_file=True,
            )
            await asyncio.to_thread(self._write_sync_token_file, sync_path, payload)
            self._last_saved_next_batch = self._next_batch
            self._last_save_at = now
            return True
        except Exception as e:
            logger.warning(f"保存同步令牌失败：{e}")
            return False


__all__ = ["SyncTokenFallbackMixin"]

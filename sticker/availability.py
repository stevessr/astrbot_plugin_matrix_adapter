"""
Sticker availability store per account.
"""

import json
from pathlib import Path

from astrbot.api import logger


class StickerAvailabilityStore:
    def __init__(self, storage_path: str | Path):
        self.file_path = Path(storage_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._ids: set[str] = set()
        self._load()

    def _load(self):
        if self.file_path.exists():
            try:
                with open(self.file_path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    self._ids = {str(x) for x in data}
            except Exception as e:
                logger.warning(f"加载 sticker 可用列表失败：{e}")
                self._ids = set()

    def _save(self):
        try:
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(sorted(self._ids), f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存 sticker 可用列表失败：{e}")

    def get_ids(self) -> set[str]:
        return set(self._ids)

    def clear(self):
        self._ids = set()
        self._save()

    def set_ids(self, ids: list[str] | set[str]):
        self._ids = {str(x) for x in ids}
        self._save()

    def add_ids(self, ids: list[str] | set[str]):
        for sticker_id in ids:
            self._ids.add(str(sticker_id))
        self._save()

"""
JSON storage backend.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from astrbot.api import logger


class JsonBackend:
    """One JSON file per key."""

    def __init__(
        self, folder_path: Path, filename_resolver: Callable[[str], str]
    ) -> None:
        self.folder_path = Path(folder_path)
        self.folder_path.mkdir(parents=True, exist_ok=True)
        self._filename_resolver = filename_resolver

    def _path_for_key(self, record_key: str) -> Path:
        return self.folder_path / self._filename_resolver(record_key)

    def get(self, record_key: str) -> Any | None:
        path = self._path_for_key(record_key)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as e:
            logger.debug(f"Failed to read json record {record_key}: {e}")
            return None

    def upsert(self, record_key: str, data: Any) -> None:
        path = self._path_for_key(record_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(data, ensure_ascii=False, indent=2)
        temp_path = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            temp_path.replace(path)
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def delete(self, record_key: str) -> None:
        path = self._path_for_key(record_key)
        try:
            path.unlink(missing_ok=True)
        except OSError as e:
            logger.debug(f"Failed to delete json record {record_key}: {e}")

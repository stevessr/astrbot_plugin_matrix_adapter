"""
Matrix user profile store for interacted accounts.

Stores display name and avatar URL under plugin data dir / users.
"""

import json
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.star import StarTools

from .storage_paths import MatrixStoragePaths


class MatrixUserStore:
    """Persist interacted user profiles (display name + avatar URL)."""

    def __init__(self, data_dir: Path | None = None) -> None:
        if data_dir is None:
            try:
                data_dir = StarTools.get_data_dir("astrbot_plugin_matrix_adapter")
            except Exception:
                data_dir = Path("./data/astrbot_plugin_matrix_adapter")
        self._users_dir = data_dir / "users"
        self._users_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, dict[str, Any]] = {}

    def _user_path(self, user_id: str) -> Path:
        safe_user = MatrixStoragePaths.sanitize_username(user_id)
        if not safe_user:
            safe_user = "unknown"
        return self._users_dir / f"{safe_user}.json"

    def get(self, user_id: str) -> dict[str, Any] | None:
        if not user_id:
            return None
        if user_id in self._cache:
            return self._cache[user_id]
        path = self._user_path(user_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict):
                self._cache[user_id] = data
                return data
        except Exception as e:
            logger.debug(f"Failed to read user profile {user_id}: {e}")
        return None

    def upsert(self, user_id: str, display_name: str | None, avatar_url: str | None):
        if not user_id:
            return
        existing = self.get(user_id) or {"user_id": user_id}
        updated = False

        if display_name and display_name != existing.get("display_name"):
            existing["display_name"] = display_name
            updated = True
        if avatar_url and avatar_url != existing.get("avatar_url"):
            existing["avatar_url"] = avatar_url
            updated = True

        if not updated:
            return

        path = self._user_path(user_id)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(existing, ensure_ascii=False, indent=2))
            self._cache[user_id] = existing
        except Exception as e:
            logger.debug(f"Failed to save user profile {user_id}: {e}")

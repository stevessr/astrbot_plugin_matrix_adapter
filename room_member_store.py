"""
Matrix room member store for persisting room member information.

Stores member list and metadata under plugin data dir / rooms.
"""

import json
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.star import StarTools

from .storage_paths import MatrixStoragePaths


class MatrixRoomMemberStore:
    """Persist room member lists and metadata."""

    def __init__(self, data_dir: Path | None = None) -> None:
        if data_dir is None:
            try:
                data_dir = StarTools.get_data_dir("astrbot_plugin_matrix_adapter")
            except Exception:
                data_dir = Path("./data/astrbot_plugin_matrix_adapter")
        self._rooms_dir = data_dir / "rooms"
        self._rooms_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, dict[str, Any]] = {}

    def _room_path(self, room_id: str) -> Path:
        safe_room = MatrixStoragePaths.sanitize_username(room_id)
        if not safe_room:
            safe_room = "unknown"
        return self._rooms_dir / f"{safe_room}.json"

    def get(self, room_id: str) -> dict[str, Any] | None:
        """Get room member data from storage."""
        if not room_id:
            return None
        if room_id in self._cache:
            return self._cache[room_id]
        path = self._room_path(room_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict):
                self._cache[room_id] = data
                return data
        except Exception as e:
            logger.debug(f"Failed to read room member data {room_id}: {e}")
        return None

    def upsert(
        self,
        room_id: str,
        members: dict[str, str],
        member_avatars: dict[str, str],
        member_count: int,
        is_direct: bool | None = None,
    ):
        """
        Save or update room member data.

        Args:
            room_id: Room ID
            members: Dictionary mapping user_id to display_name
            member_avatars: Dictionary mapping user_id to avatar URL
            member_count: Total number of members
            is_direct: Whether this is a direct message room
        """
        if not room_id:
            return

        existing = self.get(room_id)
        updated = False

        # If no existing data, this is a new entry
        if not existing:
            existing = {"room_id": room_id}
            updated = True
        else:
            # Check if data has changed
            if members != existing.get("members"):
                existing["members"] = members
                updated = True

            if member_avatars != existing.get("member_avatars"):
                existing["member_avatars"] = member_avatars
                updated = True

            if member_count != existing.get("member_count"):
                existing["member_count"] = member_count
                updated = True

            if is_direct is not None and is_direct != existing.get("is_direct"):
                existing["is_direct"] = is_direct
                updated = True

        # Always update the data if it's a new entry or changed
        if updated:
            existing["members"] = members
            existing["member_avatars"] = member_avatars
            existing["member_count"] = member_count
            if is_direct is not None:
                existing["is_direct"] = is_direct
            existing["updated_at"] = int(Path(__file__).stat().st_mtime)

            path = self._room_path(room_id)
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(existing, ensure_ascii=False, indent=2))
                self._cache[room_id] = existing
                logger.info(f"已保存房间成员数据：{room_id} ({member_count} 个成员)")
            except Exception as e:
                logger.error(f"保存房间成员数据失败 {room_id}: {e}")

    def delete(self, room_id: str):
        """Delete room member data from storage."""
        if not room_id:
            return
        path = self._room_path(room_id)
        try:
            if path.exists():
                path.unlink()
            if room_id in self._cache:
                del self._cache[room_id]
            logger.debug(f"Deleted room member data: {room_id}")
        except Exception as e:
            logger.debug(f"Failed to delete room member data {room_id}: {e}")
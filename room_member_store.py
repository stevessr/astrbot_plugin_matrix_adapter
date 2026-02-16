"""
Matrix room member store for persisting room member information.

Stores member list and metadata under plugin data dir / rooms.
"""

import time
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.star import StarTools

from .storage_backend import MatrixFolderDataStore, StorageBackendConfig
from .storage_paths import MatrixStoragePaths


class MatrixRoomMemberStore:
    """Persist room member lists and metadata."""

    def __init__(
        self,
        data_dir: Path | None = None,
        *,
        storage_backend_config: StorageBackendConfig,
    ) -> None:
        if data_dir is None:
            try:
                data_dir = StarTools.get_data_dir("astrbot_plugin_matrix_adapter")
            except Exception:
                data_dir = Path("./data/astrbot_plugin_matrix_adapter")
        self._rooms_dir = data_dir / "rooms"
        self._rooms_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, dict[str, Any]] = {}

        self._storage_backend_config = storage_backend_config
        self._storage_backend = self._storage_backend_config.backend
        self._pgsql_dsn = self._storage_backend_config.pgsql_dsn
        self._pgsql_schema = self._storage_backend_config.pgsql_schema
        self._pgsql_table_prefix = self._storage_backend_config.pgsql_table_prefix

        self._store = self._build_store()

    @staticmethod
    def _json_filename(room_id: str) -> str:
        safe_room = MatrixStoragePaths.sanitize_username(room_id)
        if not safe_room:
            safe_room = "unknown"
        return f"{safe_room}.json"

    def _build_store(self) -> MatrixFolderDataStore:
        try:
            return MatrixFolderDataStore(
                folder_path=self._rooms_dir,
                namespace_key="rooms",
                backend=self._storage_backend,
                json_filename_resolver=self._json_filename,
                pgsql_dsn=self._pgsql_dsn,
                pgsql_schema=self._pgsql_schema,
                pgsql_table_prefix=self._pgsql_table_prefix,
            )
        except Exception as e:
            logger.warning(
                f"初始化房间存储后端 {self._storage_backend} 失败，回退 json: {e}"
            )
            return MatrixFolderDataStore(
                folder_path=self._rooms_dir,
                namespace_key="rooms",
                backend="json",
                json_filename_resolver=self._json_filename,
            )

    def get(self, room_id: str) -> dict[str, Any] | None:
        """Get room member data from storage."""
        if not room_id:
            return None
        if room_id in self._cache:
            return self._cache[room_id]
        try:
            data = self._store.get(room_id)
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
        room_name: str | None = None,
        topic: str | None = None,
        avatar_url: str | None = None,
        join_rules: dict[str, Any] | None = None,
        power_levels: dict[str, Any] | None = None,
        history_visibility: str | None = None,
        guest_access: str | None = None,
        canonical_alias: str | None = None,
        room_aliases: list[str] | None = None,
        encryption: dict[str, Any] | None = None,
        create: dict[str, Any] | None = None,
        tombstone: dict[str, Any] | None = None,
        pinned_events: list[str] | None = None,
        space_children: dict[str, dict[str, Any]] | None = None,
        space_parents: dict[str, dict[str, Any]] | None = None,
        third_party_invites: dict[str, dict[str, Any]] | None = None,
        state_events: dict[str, dict[str, Any]] | None = None,
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

            if room_name is not None and room_name != existing.get("room_name"):
                existing["room_name"] = room_name
                updated = True

            if topic is not None and topic != existing.get("topic"):
                existing["topic"] = topic
                updated = True

            if avatar_url is not None and avatar_url != existing.get("avatar_url"):
                existing["avatar_url"] = avatar_url
                updated = True

            if join_rules is not None and join_rules != existing.get("join_rules"):
                existing["join_rules"] = join_rules
                updated = True

            if power_levels is not None and power_levels != existing.get(
                "power_levels"
            ):
                existing["power_levels"] = power_levels
                updated = True

            if history_visibility is not None and history_visibility != existing.get(
                "history_visibility"
            ):
                existing["history_visibility"] = history_visibility
                updated = True

            if guest_access is not None and guest_access != existing.get(
                "guest_access"
            ):
                existing["guest_access"] = guest_access
                updated = True

            if canonical_alias is not None and canonical_alias != existing.get(
                "canonical_alias"
            ):
                existing["canonical_alias"] = canonical_alias
                updated = True

            if room_aliases is not None and room_aliases != existing.get(
                "room_aliases"
            ):
                existing["room_aliases"] = room_aliases
                updated = True

            if encryption is not None and encryption != existing.get("encryption"):
                existing["encryption"] = encryption
                updated = True

            if create is not None and create != existing.get("create"):
                existing["create"] = create
                updated = True

            if tombstone is not None and tombstone != existing.get("tombstone"):
                existing["tombstone"] = tombstone
                updated = True

            if pinned_events is not None and pinned_events != existing.get(
                "pinned_events"
            ):
                existing["pinned_events"] = pinned_events
                updated = True

            if space_children is not None and space_children != existing.get(
                "space_children"
            ):
                existing["space_children"] = space_children
                updated = True

            if space_parents is not None and space_parents != existing.get(
                "space_parents"
            ):
                existing["space_parents"] = space_parents
                updated = True

            if third_party_invites is not None and third_party_invites != existing.get(
                "third_party_invites"
            ):
                existing["third_party_invites"] = third_party_invites
                updated = True

            if state_events is not None and state_events != existing.get(
                "state_events"
            ):
                existing["state_events"] = state_events
                updated = True

        # Always update the data if it's a new entry or changed
        if updated:
            existing["members"] = members
            existing["member_avatars"] = member_avatars
            existing["member_count"] = member_count
            if is_direct is not None:
                existing["is_direct"] = is_direct
            if room_name is not None:
                existing["room_name"] = room_name
            if topic is not None:
                existing["topic"] = topic
            if avatar_url is not None:
                existing["avatar_url"] = avatar_url
            if join_rules is not None:
                existing["join_rules"] = join_rules
            if power_levels is not None:
                existing["power_levels"] = power_levels
            if history_visibility is not None:
                existing["history_visibility"] = history_visibility
            if guest_access is not None:
                existing["guest_access"] = guest_access
            if canonical_alias is not None:
                existing["canonical_alias"] = canonical_alias
            if room_aliases is not None:
                existing["room_aliases"] = room_aliases
            if encryption is not None:
                existing["encryption"] = encryption
            if create is not None:
                existing["create"] = create
            if tombstone is not None:
                existing["tombstone"] = tombstone
            if pinned_events is not None:
                existing["pinned_events"] = pinned_events
            if space_children is not None:
                existing["space_children"] = space_children
            if space_parents is not None:
                existing["space_parents"] = space_parents
            if third_party_invites is not None:
                existing["third_party_invites"] = third_party_invites
            if state_events is not None:
                existing["state_events"] = state_events
            existing["updated_at"] = int(time.time())

            try:
                self._store.upsert(room_id, existing)
                self._cache[room_id] = existing
                logger.info(f"已保存房间成员数据：{room_id} ({member_count} 个成员)")
            except Exception as e:
                logger.error(f"保存房间成员数据失败 {room_id}: {e}")

    def delete(self, room_id: str):
        """Delete room member data from storage."""
        if not room_id:
            return
        try:
            self._store.delete(room_id)
            if room_id in self._cache:
                del self._cache[room_id]
            logger.debug(f"Deleted room member data: {room_id}")
        except Exception as e:
            logger.debug(f"Failed to delete room member data {room_id}: {e}")

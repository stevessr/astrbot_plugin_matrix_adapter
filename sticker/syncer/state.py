"""Sticker synchronization state and pack metadata helpers."""

import asyncio
from typing import Any

from ...constants import M_IMAGE_PACK_ROOMS, M_ROOM_IMAGE_PACK
from ..availability import StickerAvailabilityStore
from ..storage_lib import StickerStorage


class StickerSyncStateMixin:
    # 支持的 sticker 包事件类型
    ROOM_EMOTES_TYPE = "im.ponies.room_emotes"
    USER_EMOTES_TYPE = "im.ponies.user_emotes"
    ROOM_IMAGE_PACK_TYPE = M_ROOM_IMAGE_PACK
    USER_IMAGE_PACK_ROOMS_TYPE = M_IMAGE_PACK_ROOMS
    # 非标准备用类型（某些旧客户端使用）
    ROOM_EMOTES_ALT = "m.room.sticker_pack"
    ROOM_PACK_TYPES = frozenset(
        {ROOM_IMAGE_PACK_TYPE, ROOM_EMOTES_TYPE, ROOM_EMOTES_ALT}
    )

    def __init__(
        self,
        storage: StickerStorage,
        client=None,
        availability_store: StickerAvailabilityStore | None = None,
    ):
        """初始化同步器。"""
        self.storage = storage
        self.client = client
        self.availability_store = availability_store
        self._synced_rooms: set[str] = set()
        self._sync_lock = asyncio.Lock()

    def set_client(self, client):
        """设置 Matrix 客户端"""
        self.client = client

    def reset_available(self):
        if self.availability_store:
            self.availability_store.clear()

    def _get_pack_name(self, content: dict, state_key: str, room_id: str) -> str:
        """从事件内容提取包名称"""
        pack_info = content.get("pack", {})
        if isinstance(pack_info, dict) and pack_info.get("display_name"):
            return pack_info["display_name"]

        if state_key:
            return state_key

        return f"room_{(room_id or '')[:8]}"

    @staticmethod
    def _supports_stickers(content: dict[str, Any]) -> bool:
        """Whether an MSC2545 pack is intended for standalone stickers."""
        pack = content.get("pack")
        if not isinstance(pack, dict):
            return True
        usage = pack.get("usage")
        # Absent/empty means all usage types according to Matrix v1.19.
        if not isinstance(usage, list) or not usage:
            return True
        return "sticker" in usage

    def clear_room_sync_cache(self, room_id: str | None = None):
        """
        清除房间同步缓存

        Args:
            room_id: 可选，指定房间。如果为 None，清除所有缓存
        """
        if room_id:
            self._synced_rooms.discard(room_id)
        else:
            self._synced_rooms.clear()


__all__ = ["StickerSyncStateMixin"]

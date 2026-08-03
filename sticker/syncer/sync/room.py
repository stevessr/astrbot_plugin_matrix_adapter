"""Room sticker-pack synchronization."""

from astrbot.api import logger


class StickerRoomSyncMixin:
    """Synchronize sticker packs declared in room state."""

    async def sync_room_stickers(self, room_id: str, force: bool = False) -> int:
        """
        同步房间的 sticker 包

        Args:
            room_id: 房间 ID
            force: 是否强制重新同步

        Returns:
            同步的 sticker 数量
        """
        if not self.client:
            logger.warning("无法同步 sticker：未设置 Matrix 客户端")
            return 0

        if room_id in self._synced_rooms and not force:
            return 0

        async with self._sync_lock:
            if room_id in self._synced_rooms and not force:
                return 0

            try:
                state = await self.client.get_room_state(room_id)
                synced_count = 0

                for event in state:
                    event_type = event.get("type", "")
                    if event_type in self.ROOM_PACK_TYPES:
                        content = event.get("content", {})
                        state_key = event.get("state_key", "")
                        if not isinstance(content, dict) or not self._supports_stickers(
                            content
                        ):
                            continue

                        pack_name = self._get_pack_name(content, state_key, room_id)
                        images = content.get("images", {})

                        if isinstance(images, dict) and images:
                            ids = await self._sync_sticker_pack(
                                pack_name=pack_name,
                                images=images,
                                room_id=room_id,
                            )
                            count = len(ids)
                            synced_count += count
                            if self.availability_store and ids:
                                self.availability_store.add_ids(ids)
                            logger.info(
                                f"同步房间 {room_id} 的 sticker 包 '{pack_name}'：{count} 个"
                            )

                self._synced_rooms.add(room_id)
                return synced_count

            except Exception as e:
                logger.error(f"同步房间 {room_id} 的 sticker 包失败：{e}")
                return 0

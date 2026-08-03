"""User-level sticker-pack synchronization."""

from astrbot.api import logger


class StickerUserSyncMixin:
    """Synchronize sticker packs from account data and referenced rooms."""

    async def sync_user_stickers(self) -> int:
        """
        同步用户的 sticker 包

        Returns:
            同步的 sticker 数量
        """
        if not self.client:
            logger.warning("无法同步用户 sticker：未设置 Matrix 客户端")
            return 0

        try:
            synced_ids: set[str] = set()

            account_data = await self.client.get_global_account_data(
                self.USER_EMOTES_TYPE
            )
            images = (
                account_data.get("images", {}) if isinstance(account_data, dict) else {}
            )
            if isinstance(images, dict) and images:
                ids = await self._sync_sticker_pack(
                    pack_name="user_emotes",
                    images=images,
                    room_id=None,
                    is_user_pack=True,
                )
                synced_ids.update(ids)
                logger.info(f"同步旧版用户 sticker 包：{len(ids)} 个")

            references = await self.client.get_global_account_data(
                self.USER_IMAGE_PACK_ROOMS_TYPE
            )
            rooms = references.get("rooms", {}) if isinstance(references, dict) else {}
            if isinstance(rooms, dict):
                for room_id, state_keys in rooms.items():
                    if not isinstance(room_id, str) or not isinstance(state_keys, dict):
                        continue
                    for state_key in state_keys:
                        if not isinstance(state_key, str):
                            continue
                        try:
                            content = await self.client.get_room_state_event(
                                room_id,
                                self.ROOM_IMAGE_PACK_TYPE,
                                state_key,
                            )
                            if not isinstance(
                                content, dict
                            ) or not self._supports_stickers(content):
                                continue
                            pack_images = content.get("images", {})
                            if not isinstance(pack_images, dict) or not pack_images:
                                continue
                            ids = await self._sync_sticker_pack(
                                pack_name=self._get_pack_name(
                                    content, state_key, room_id
                                ),
                                images=pack_images,
                                room_id=room_id,
                                is_user_pack=True,
                            )
                            synced_ids.update(ids)
                            logger.info(
                                "同步全局 image pack "
                                f"{room_id}/{state_key!r}：{len(ids)} 个"
                            )
                        except Exception as e:
                            logger.warning(
                                "读取全局 image pack 失败："
                                f"{room_id}/{state_key!r}: {e}"
                            )

            if self.availability_store and synced_ids:
                self.availability_store.add_ids(synced_ids)
            if not synced_ids:
                logger.debug("用户没有可用的自定义 sticker 包")
            return len(synced_ids)

        except Exception as e:
            logger.error(f"同步用户 sticker 包失败：{e}")
            return 0

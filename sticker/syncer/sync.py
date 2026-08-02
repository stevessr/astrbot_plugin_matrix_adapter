"""Sticker pack synchronization operations."""

from typing import Any

from astrbot.api import logger

from ..component import Sticker, StickerInfo


class StickerPackOperationsMixin:
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

    async def _sync_sticker_pack(
        self,
        pack_name: str,
        images: dict[str, Any],
        room_id: str | None = None,
        is_user_pack: bool = False,
    ) -> set[str]:
        """
        同步单个 sticker 包

        Args:
            pack_name: 包名称
            images: sticker 图片字典 {shortcode: {url, info, ...}}
            room_id: 可选，房间 ID
            is_user_pack: 是否是用户级别的包

        Returns:
            同步的 sticker 数量
        """
        synced_ids: set[str] = set()

        for shortcode, sticker_data in images.items():
            try:
                mxc_url = sticker_data.get("url")
                if not mxc_url:
                    continue

                info_data = sticker_data.get("info", {})
                info = StickerInfo(
                    mimetype=info_data.get("mimetype", "image/png"),
                    width=info_data.get("w"),
                    height=info_data.get("h"),
                    size=info_data.get("size"),
                    thumbnail_url=info_data.get("thumbnail_url"),
                )

                sticker = Sticker(
                    body=sticker_data.get("body", shortcode),
                    url=mxc_url,
                    info=info,
                    mxc_url=mxc_url,
                    pack_name=pack_name,
                )

                tags = [shortcode]
                if room_id:
                    tags.append(f"room:{(room_id or '')[:20]}")
                if is_user_pack:
                    tags.append("user")

                meta = await self.storage.save_sticker(
                    sticker=sticker,
                    client=self.client,
                    pack_name=pack_name,
                    room_id=room_id,
                    tags=tags,
                )
                synced_ids.add(meta.sticker_id)

            except Exception as e:
                logger.warning(f"同步 sticker '{shortcode}' 失败：{e}")
                continue

        return synced_ids


__all__ = ["StickerPackOperationsMixin"]

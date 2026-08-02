"""Sticker pack discovery and query operations."""

from astrbot.api import logger

from .models import StickerPackInfo


class StickerPackQueryMixin:
    async def get_room_sticker_packs(self, room_id: str) -> list[StickerPackInfo]:
        """
        获取房间的 sticker 包信息（不下载）

        Args:
            room_id: 房间 ID

        Returns:
            StickerPackInfo 列表
        """
        if not self.client:
            return []

        packs = []

        try:
            state = await self.client.get_room_state(room_id)

            for event in state:
                event_type = event.get("type", "")

                if event_type in self.ROOM_PACK_TYPES:
                    content = event.get("content", {})
                    state_key = event.get("state_key", "")
                    if not isinstance(content, dict) or not self._supports_stickers(
                        content
                    ):
                        continue
                    pack_info = content.get("pack", {})
                    images = content.get("images", {})

                    if not isinstance(pack_info, dict):
                        pack_info = {}
                    if not isinstance(images, dict):
                        images = {}

                    pack = StickerPackInfo(
                        pack_name=self._get_pack_name(content, state_key, room_id),
                        display_name=pack_info.get("display_name", state_key),
                        avatar_url=pack_info.get("avatar_url"),
                        sticker_count=len(images),
                        room_id=room_id,
                        is_user_pack=False,
                    )
                    packs.append(pack)

        except Exception as e:
            logger.error(f"获取房间 {room_id} 的 sticker 包信息失败：{e}")

        return packs


__all__ = ["StickerPackQueryMixin"]

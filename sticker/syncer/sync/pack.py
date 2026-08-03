"""Single sticker-pack persistence operations."""

from typing import Any

from astrbot.api import logger

from ...component import Sticker, StickerInfo


class StickerPackSyncMixin:
    """Convert and persist the stickers in one pack."""

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

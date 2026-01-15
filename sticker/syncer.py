"""
Matrix Sticker 包同步器

自动同步房间和用户的 sticker 包
支持 MSC2545 格式 (im.ponies.room_emotes / im.ponies.user_emotes)
"""

import asyncio
from dataclasses import dataclass
from typing import Any

from astrbot.api import logger

from .availability import StickerAvailabilityStore
from .component import Sticker, StickerInfo
from .storage import StickerStorage


@dataclass
class StickerPackInfo:
    """Sticker 包信息"""

    pack_name: str
    display_name: str
    avatar_url: str | None
    sticker_count: int
    room_id: str | None  # 如果是房间 sticker 包
    is_user_pack: bool  # 是否是用户级别的包


class StickerPackSyncer:
    """
    Sticker 包同步器

    负责：
    - 从房间状态事件读取 sticker 包 (im.ponies.room_emotes)
    - 从用户账户数据读取 sticker 包 (im.ponies.user_emotes)
    - 同步 sticker 包到本地存储
    """

    # 支持的 sticker 包事件类型
    ROOM_EMOTES_TYPE = "im.ponies.room_emotes"
    USER_EMOTES_TYPE = "im.ponies.user_emotes"
    # 备用类型（某些服务器使用）
    ROOM_EMOTES_ALT = "m.room.sticker_pack"

    def __init__(
        self,
        storage: StickerStorage,
        client=None,
        availability_store: StickerAvailabilityStore | None = None,
    ):
        """
        初始化同步器

        Args:
            storage: StickerStorage 实例
            client: MatrixHTTPClient 实例
        """
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

        # 避免重复同步
        if room_id in self._synced_rooms and not force:
            return 0

        async with self._sync_lock:
            if room_id in self._synced_rooms and not force:
                return 0

            try:
                # 获取房间状态
                state = await self.client.get_room_state(room_id)

                synced_count = 0

                for event in state:
                    event_type = event.get("type", "")

                    # 检查是否是 sticker 包事件
                    if event_type in [self.ROOM_EMOTES_TYPE, self.ROOM_EMOTES_ALT]:
                        content = event.get("content", {})
                        state_key = event.get("state_key", "")

                        # 解析 sticker 包
                        pack_name = self._get_pack_name(content, state_key, room_id)
                        images = content.get("images", {})

                        if images:
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
            # 获取用户账户数据
            account_data = await self.client.get_global_account_data(
                self.USER_EMOTES_TYPE
            )

            if not account_data:
                logger.debug("用户没有自定义 sticker 包")
                return 0

            synced_count = 0
            images = account_data.get("images", {})

            if images:
                ids = await self._sync_sticker_pack(
                    pack_name="user_emotes",
                    images=images,
                    room_id=None,
                    is_user_pack=True,
                )
                count = len(ids)
                synced_count += count
                if self.availability_store and ids:
                    self.availability_store.add_ids(ids)
                logger.info(f"同步用户 sticker 包：{count} 个")

            return synced_count

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

                # 解析 sticker 信息
                info_data = sticker_data.get("info", {})
                info = StickerInfo(
                    mimetype=info_data.get("mimetype", "image/png"),
                    width=info_data.get("w"),
                    height=info_data.get("h"),
                    size=info_data.get("size"),
                    thumbnail_url=info_data.get("thumbnail_url"),
                )

                # 创建 Sticker 对象
                sticker = Sticker(
                    body=sticker_data.get("body", shortcode),
                    url=mxc_url,
                    info=info,
                    mxc_url=mxc_url,
                    pack_name=pack_name,
                )

                # 使用 shortcode 作为标签
                tags = [shortcode]
                if room_id:
                    tags.append(f"room:{room_id[:20]}")
                if is_user_pack:
                    tags.append("user")

                # 保存到存储（会自动下载并缓存）
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

    def _get_pack_name(self, content: dict, state_key: str, room_id: str) -> str:
        """从事件内容提取包名称"""
        # 优先使用 pack 中的 display_name
        pack_info = content.get("pack", {})
        if pack_info.get("display_name"):
            return pack_info["display_name"]

        # 其次使用 state_key
        if state_key:
            return state_key

        # 最后使用房间 ID 的简短形式
        return f"room_{room_id[:8]}"

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

                if event_type in [self.ROOM_EMOTES_TYPE, self.ROOM_EMOTES_ALT]:
                    content = event.get("content", {})
                    state_key = event.get("state_key", "")
                    pack_info = content.get("pack", {})
                    images = content.get("images", {})

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

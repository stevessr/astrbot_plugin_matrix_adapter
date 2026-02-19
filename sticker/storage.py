"""
Matrix Sticker 存储管理

提供 sticker 的本地缓存、索引和检索功能
类似 image 的缓存方案
"""

import json
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.star import StarTools

from .availability import StickerAvailabilityStore
from .component import Sticker, StickerInfo


def _get_sticker_storage_path() -> Path:
    """获取 sticker 存储路径

    优先使用 StarTools.get_data_dir() 获取插件数据目录，
    如果失败则回退到默认路径。
    """
    try:
        # 使用插件数据目录：data/plugin_data/astrbot_plugin_matrix_adapter/sticker
        data_dir = StarTools.get_data_dir("astrbot_plugin_matrix_adapter")
        return data_dir / "sticker"
    except Exception:
        # 回退到旧路径（兼容性）
        from astrbot.core.utils.astrbot_path import get_astrbot_data_path

        return Path(get_astrbot_data_path()) / "matrix_sticker"


@dataclass
class StickerMeta:
    """Sticker 元数据，用于索引"""

    sticker_id: str
    body: str
    mxc_url: str
    local_path: str | None
    mimetype: str
    width: int | None
    height: int | None
    pack_name: str | None
    room_id: str | None
    created_at: float
    last_used: float
    use_count: int = 0
    tags: list[str] | None = None


class StickerStorage:
    """
    Sticker 存储管理器

    负责：
    - 缓存 sticker 文件到本地
    - 维护 sticker 索引（JSON 文件）
    - 根据 ID、名称、标签检索 sticker
    """

    def __init__(
        self,
        storage_path: str | None = None,
        availability_store: StickerAvailabilityStore | None = None,
    ):
        """
        初始化存储管理器

        Args:
            storage_path: 可选，自定义存储路径
        """
        if storage_path:
            self.storage_dir = Path(storage_path)
        else:
            self.storage_dir = _get_sticker_storage_path()

        # 确保目录存在
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir = self.storage_dir / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # 索引文件
        self.index_file = self.storage_dir / "sticker_index.json"

        # 可用性过滤（按账号）
        self.availability_store = availability_store

        # 加载索引
        self._index: dict[str, StickerMeta] = {}
        self._load_index()

    def _load_index(self):
        """从文件加载索引"""
        if self.index_file.exists():
            try:
                with open(self.index_file, encoding="utf-8") as f:
                    data = json.load(f)
                    self._index = {}
                    for sticker_id, meta_dict in data.items():
                        # 兼容旧版本，添加缺失的字段
                        if "tags" not in meta_dict:
                            meta_dict["tags"] = None
                        if "room_id" not in meta_dict:
                            meta_dict["room_id"] = None
                        self._index[sticker_id] = StickerMeta(**meta_dict)
            except Exception as e:
                logger.warning(f"加载 sticker 索引失败：{e}")
                self._index = {}

    def reload_index(self):
        """重新加载索引（用于同步多个实例）"""
        self._load_index()

    def _save_index(self):
        """保存索引到文件"""
        try:
            data = {
                sticker_id: asdict(meta) for sticker_id, meta in self._index.items()
            }
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存 sticker 索引失败：{e}")

    def _sanitize_segment(self, name: str) -> str:
        safe = re.sub(r"[^\w\-\.]+", "_", name.strip()) if name else "unknown"
        return safe[:80] if len(safe) > 80 else safe

    def _generate_cache_path(
        self,
        sticker_id: str,
        mimetype: str,
        room_id: str | None = None,
        pack_name: str | None = None,
    ) -> Path:
        """生成缓存文件路径"""
        # 根据 mimetype 确定扩展名
        ext_map = {
            "image/png": ".png",
            "image/jpeg": ".jpg",
            "image/gif": ".gif",
            "image/webp": ".webp",
        }
        ext = ext_map.get(mimetype, ".png")
        room_seg = f"room_{self._sanitize_segment(room_id)}" if room_id else "user"
        pack_seg = self._sanitize_segment(pack_name or "default")
        cache_dir = self.cache_dir / room_seg / pack_seg
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir / f"{sticker_id}{ext}"

    async def save_sticker(
        self,
        sticker: Sticker,
        file_data: bytes | None = None,
        client=None,
        pack_name: str | None = None,
        room_id: str | None = None,
        tags: list[str] | None = None,
    ) -> StickerMeta:
        """
        保存 sticker 到本地存储

        Args:
            sticker: Sticker 对象
            file_data: 可选，sticker 文件数据
            client: 可选，Matrix HTTP client（用于从 mxc:// 下载）
            pack_name: 可选，sticker 包名称
            tags: 可选，标签列表

        Returns:
            StickerMeta: 保存后的元数据
        """
        # 生成 sticker ID
        sticker_id = sticker.generate_sticker_id()

        # 如果已存在，更新使用信息
        if sticker_id in self._index:
            meta = self._index[sticker_id]
            meta.last_used = time.time()
            meta.use_count += 1
            if pack_name:
                meta.pack_name = pack_name
            if tags:
                meta.tags = tags
            self._save_index()
            return meta

        # 确定缓存路径
        cache_path = self._generate_cache_path(
            sticker_id,
            sticker.info.mimetype,
            room_id=room_id,
            pack_name=pack_name or sticker.pack_name,
        )

        # 获取文件数据
        if file_data is None:
            if sticker.url.startswith("mxc://") and client:
                # 从 Matrix 媒体服务器下载
                try:
                    file_data = await client.download_file(
                        sticker.url, allow_thumbnail_fallback=True
                    )
                except Exception as e:
                    logger.error(f"下载 sticker 失败：{e}")
                    raise
            elif not sticker.url.startswith("mxc://"):
                # 从本地或 HTTP URL 获取
                try:
                    file_path = await sticker.convert_to_file_path()
                    with open(file_path, "rb") as f:
                        file_data = f.read()
                except Exception as e:
                    logger.error(f"获取 sticker 文件失败：{e}")
                    raise
            else:
                raise ValueError("需要提供 file_data 或 client 来下载 mxc:// URL")

        # 保存文件
        with open(cache_path, "wb") as f:
            f.write(file_data)

        # 获取图片尺寸
        width, height = sticker.info.width, sticker.info.height
        if width is None or height is None:
            try:
                from PIL import Image as PILImage

                with PILImage.open(cache_path) as img:
                    width, height = img.size
            except Exception:
                pass

        # 创建元数据
        now = time.time()
        meta = StickerMeta(
            sticker_id=sticker_id,
            body=sticker.body,
            mxc_url=sticker.mxc_url or sticker.url,
            local_path=str(cache_path),
            mimetype=sticker.info.mimetype,
            width=width,
            height=height,
            pack_name=pack_name or sticker.pack_name,
            room_id=room_id,
            created_at=now,
            last_used=now,
            use_count=1,
            tags=tags,
        )

        # 更新索引
        self._index[sticker_id] = meta
        self._save_index()

        logger.info(f"保存 sticker: {sticker_id} ({sticker.body})")
        return meta

    def _build_sticker_from_meta(self, sticker_id: str, meta: StickerMeta) -> Sticker:
        """从元数据构建 Sticker 对象，不修改使用计数。"""
        info = StickerInfo(
            mimetype=meta.mimetype,
            width=meta.width,
            height=meta.height,
        )

        has_mxc = meta.mxc_url and meta.mxc_url.startswith("mxc://")
        has_local = meta.local_path and os.path.exists(meta.local_path)

        if has_mxc:
            url = meta.mxc_url
        elif has_local:
            url = f"file:///{meta.local_path}"
        else:
            url = meta.mxc_url or ""

        return Sticker(
            body=meta.body,
            url=url,
            info=info,
            mxc_url=meta.mxc_url if has_mxc else None,
            sticker_id=sticker_id,
            pack_name=meta.pack_name,
        )

    def get_sticker(self, sticker_id: str, update_usage: bool = True) -> Sticker | None:
        """
        根据 ID 获取 sticker

        Args:
            sticker_id: sticker ID
            update_usage: 是否更新使用计数与最近使用时间

        Returns:
            Sticker 对象，如果不存在返回 None
        """
        if sticker_id not in self._index:
            return None

        meta = self._index[sticker_id]

        if update_usage:
            meta.last_used = time.time()
            meta.use_count += 1
            self._save_index()

        return self._build_sticker_from_meta(sticker_id, meta)

    def find_stickers(
        self,
        query: str | None = None,
        pack_name: str | None = None,
        tags: list[str] | None = None,
        limit: int = 20,
        available_ids: set[str] | None = None,
    ) -> list[Sticker]:
        """
        搜索 sticker

        Args:
            query: 搜索关键词（匹配 body）
            pack_name: 按包名过滤
            tags: 按标签过滤
            limit: 返回数量限制

        Returns:
            匹配的 Sticker 列表
        """
        results = []

        if available_ids is None and self.availability_store:
            available_ids = self.availability_store.get_ids()

        for sticker_id, meta in self._index.items():
            if available_ids is not None and sticker_id not in available_ids:
                continue
            # 应用过滤条件
            if pack_name and meta.pack_name != pack_name:
                continue

            if tags and meta.tags:
                if not any(tag in meta.tags for tag in tags):
                    continue

            if query:
                query_lower = query.lower()
                if (
                    query_lower not in meta.body.lower()
                    and query_lower not in (meta.pack_name or "").lower()
                ):
                    continue

            # 创建 Sticker 对象
            sticker = self.get_sticker(sticker_id, update_usage=False)
            if sticker:
                results.append(sticker)

            if len(results) >= limit:
                break

        return results

    def list_stickers(
        self,
        pack_name: str | None = None,
        limit: int = 50,
        available_ids: set[str] | None = None,
    ) -> list[StickerMeta]:
        """
        列出所有 sticker

        Args:
            pack_name: 可选，按包名过滤
            limit: 返回数量限制

        Returns:
            StickerMeta 列表
        """
        results = []
        if available_ids is None and self.availability_store:
            available_ids = self.availability_store.get_ids()

        for sticker_id, meta in self._index.items():
            if available_ids is not None and sticker_id not in available_ids:
                continue
            if pack_name and meta.pack_name != pack_name:
                continue
            results.append(meta)
            if len(results) >= limit:
                break
        return results

    def list_packs(self) -> list[str]:
        """
        列出所有 sticker 包名称

        Returns:
            包名称列表
        """
        packs = set()
        available_ids = (
            self.availability_store.get_ids() if self.availability_store else None
        )
        for sticker_id, meta in self._index.items():
            if available_ids is not None and sticker_id not in available_ids:
                continue
            if meta.pack_name:
                packs.add(meta.pack_name)
        return sorted(packs)

    def delete_sticker(self, sticker_id: str) -> bool:
        """
        删除 sticker

        Args:
            sticker_id: sticker ID

        Returns:
            是否成功删除
        """
        if sticker_id not in self._index:
            return False

        meta = self._index[sticker_id]

        # 删除缓存文件
        if meta.local_path and os.path.exists(meta.local_path):
            try:
                os.remove(meta.local_path)
            except Exception as e:
                logger.warning(f"删除 sticker 缓存文件失败：{e}")

        # 从索引中移除
        del self._index[sticker_id]
        self._save_index()

        logger.info(f"删除 sticker: {sticker_id}")
        return True

    def clear_cache(self, older_than_days: int | None = None):
        """
        清理缓存

        Args:
            older_than_days: 可选，只清理超过指定天数的缓存
        """
        now = time.time()
        to_delete = []

        for sticker_id, meta in self._index.items():
            if older_than_days:
                age_days = (now - meta.last_used) / 86400
                if age_days < older_than_days:
                    continue
            to_delete.append(sticker_id)

        for sticker_id in to_delete:
            self.delete_sticker(sticker_id)

        logger.info(f"清理了 {len(to_delete)} 个 sticker 缓存")

    def get_stats(self) -> dict[str, Any]:
        """
        获取存储统计信息

        Returns:
            统计信息字典
        """
        total_count = len(self._index)
        total_size = 0
        packs = set()

        for meta in self._index.values():
            if meta.local_path and os.path.exists(meta.local_path):
                total_size += os.path.getsize(meta.local_path)
            if meta.pack_name:
                packs.add(meta.pack_name)

        return {
            "total_count": total_count,
            "total_size_mb": round(total_size / 1024 / 1024, 2),
            "pack_count": len(packs),
            "packs": sorted(packs),
        }

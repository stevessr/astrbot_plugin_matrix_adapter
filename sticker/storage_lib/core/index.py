"""Sticker index persistence and metadata helpers."""

import json
import os
from dataclasses import asdict
from pathlib import Path

from astrbot.api import logger

from ..meta import StickerMeta


class StickerStorageIndexMixin:
    """Load, persist, and fingerprint the sticker metadata index."""

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

    def save_index(self):
        """保存索引到文件。"""
        self._save_index()

    def get_sticker_meta(self, sticker_id: str) -> StickerMeta | None:
        """按 ID 获取 sticker 元数据。"""
        return self._index.get(sticker_id)

    def iter_sticker_metas(self):
        """遍历全部 sticker 元数据。"""
        return iter(self._index.values())

    def build_meta_fingerprint(self, meta: StickerMeta) -> str:
        """构建用于外部索引同步的稳定指纹。"""
        local_path = str(meta.local_path or "").strip()
        stat_sig = "missing"
        if local_path and os.path.exists(local_path):
            try:
                stat = Path(local_path).stat()
                stat_sig = f"{int(stat.st_mtime_ns)}:{int(stat.st_size)}"
            except OSError:
                stat_sig = "stat_error"
        tags = [str(tag).strip() for tag in (meta.tags or []) if str(tag).strip()]
        return "|".join(
            [
                str(meta.sticker_id or ""),
                str(meta.body or ""),
                str(meta.pack_name or ""),
                str(meta.room_id or ""),
                ",".join(sorted(tags)),
                str(meta.mxc_url or ""),
                str(meta.mimetype or ""),
                stat_sig,
            ]
        )

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

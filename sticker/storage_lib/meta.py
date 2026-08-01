"""Sticker 元数据与存储路径辅助

与 StickerStorage 核心逻辑分离，避免循环依赖。
"""

import re
from dataclasses import dataclass
from pathlib import Path

from astrbot.api.star import StarTools


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


def _sanitize_segment(name: str) -> str:
    safe = re.sub(r"[^\w\-\.]+", "_", name.strip()) if name else "unknown"
    return safe[:80] if len(safe) > 80 else safe

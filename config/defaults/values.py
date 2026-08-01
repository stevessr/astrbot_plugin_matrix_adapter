"""Plugin configuration constants and default data paths."""

from pathlib import Path

from astrbot.api.star import StarTools

_DEFAULT_MEDIA_UPLOAD_BLOCKED_EXTENSIONS = (
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".sh",
    ".ps1",
    ".jar",
    ".msi",
    ".scr",
    ".com",
)
_DEFAULT_MEDIA_UPLOAD_ALLOWED_MIME_RULES = (
    "image/*",
    "video/*",
    "audio/*",
    "text/*",
    "application/pdf",
    "application/json",
    "application/zip",
    "application/octet-stream",
)
_DEFAULT_HTTP_TIMEOUT_SECONDS = 120
_DEFAULT_E2EE_STORE_MAX_PENDING_WRITES = 256
_DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY = 2
_DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES = 32 * 1024 * 1024


def _get_default_data_dir() -> Path:
    """获取插件默认数据目录"""
    try:
        return StarTools.get_data_dir("astrbot_plugin_matrix_adapter")
    except Exception:
        # 如果 StarTools 未初始化（如在测试环境），返回临时默认值
        return Path("./data/plugin_data/astrbot_plugin_matrix_adapter")

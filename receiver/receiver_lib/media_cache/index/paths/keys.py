"""Media-cache key and file-extension computation."""

import mimetypes
from pathlib import Path


class MatrixReceiverMediaCacheKeysMixin:
    """Compute cache keys and guess file extensions for cached media."""

    @staticmethod
    def _media_cache_key(mxc_url: str) -> str:
        """
        生成缓存键。因为 mxc_url 本身已包含唯一的媒体 ID，
        不需要计算 hash，只需替换掉文件系统不允许的字符即可。
        """
        if mxc_url.startswith("mxc://"):
            mxc_url = mxc_url[6:]
        return mxc_url.replace("/", "_").replace("\\", "_").replace(":", "_")

    @staticmethod
    def _extract_cache_key_from_path(path: Path) -> str | None:
        """从缓存文件路径剥离后缀还原出 cache_key。"""
        name = path.name
        idx = name.rfind(".")
        # 如果存在点且后缀长度在合理范围内（如 .jpg / .heic 等），则去掉后缀
        if idx > 0 and (len(name) - idx) <= 6:
            return name[:idx]
        return name

    @staticmethod
    def _guess_media_ext(filename: str | None, mimetype: str | None) -> str:
        if filename:
            suffix = Path(filename).suffix
            if suffix:
                return suffix.lower()

        if mimetype:
            normalized_mimetype = mimetype.lower().split(";")[0].strip()
            ext_map = {
                "image/png": ".png",
                "image/jpeg": ".jpg",
                "image/gif": ".gif",
                "image/webp": ".webp",
                "video/mp4": ".mp4",
                "video/webm": ".webm",
                "video/quicktime": ".mov",
                "audio/mpeg": ".mp3",
                "audio/ogg": ".ogg",
                "audio/wav": ".wav",
                "audio/x-wav": ".wav",
            }
            mapped = ext_map.get(normalized_mimetype)
            if mapped:
                return mapped
            guessed = mimetypes.guess_extension(normalized_mimetype, strict=False)
            if guessed:
                return ".jpg" if guessed == ".jpe" else guessed

        return ".bin"

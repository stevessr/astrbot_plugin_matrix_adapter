"""Media-cache directory, key, lookup, and cleanup operations."""

import mimetypes
import time
from pathlib import Path

from astrbot.api import logger
from astrbot.core.utils import astrbot_path

from .....config.plugin import get_plugin_config


class MatrixReceiverMediaCachePathsMixin:
    """Resolve media-cache paths and garbage-collect stale files."""

    def _get_media_cache_dir(self) -> Path:
        """获取媒体文件缓存目录"""
        try:
            cache_dir = Path(get_plugin_config().media_cache_dir)
        except Exception:
            cache_dir = (
                Path(astrbot_path.get_astrbot_data_path()) / "temp" / "matrix_media"
            )

        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir

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

    def _find_existing_media_cache_file(
        self, cache_key: str, cache_dir: Path
    ) -> Path | None:
        cached = self._media_cache_index.get(cache_key)
        if cached:
            try:
                size_bytes = cached.stat().st_size
                if cached.is_file() and size_bytes > 0:
                    self._upsert_media_cache_index_entry(
                        cache_key, cached, size_bytes=size_bytes
                    )
                    return cached
            except Exception:
                pass
            self._remove_media_cache_index_entry(cache_key)

        if self._media_cache_index_store:
            try:
                indexed_path = self._media_cache_index_store.get(cache_key)
                if indexed_path and indexed_path.is_file():
                    size_bytes = indexed_path.stat().st_size
                    if size_bytes > 0:
                        self._upsert_media_cache_index_entry(
                            cache_key, indexed_path, size_bytes=size_bytes
                        )
                        return indexed_path
                if indexed_path:
                    self._remove_media_cache_index_entry(cache_key)
            except Exception as e:
                logger.debug(f"Failed to restore media cache index entry: {e}")

        try:
            for path in cache_dir.glob(f"{cache_key}*"):
                if path.is_file() and path.stat().st_size > 0:
                    self._upsert_media_cache_index_entry(
                        cache_key, path, size_bytes=path.stat().st_size
                    )
                    return path
        except Exception:
            return None
        return None

    def _build_media_cache_path(
        self, mxc_url: str, filename: str | None = None, mimetype: str | None = None
    ) -> Path:
        cache_key = self._media_cache_key(mxc_url)
        cache_dir = self._get_media_cache_dir()
        existing = self._find_existing_media_cache_file(cache_key, cache_dir)
        if existing:
            return existing

        ext = self._guess_media_ext(filename, mimetype)
        return cache_dir / f"{cache_key}{ext}"

    def gc_media_cache(self, older_than_days: int | None = None) -> int:
        """清理媒体缓存，返回删除文件数"""
        cache_dir = self._get_media_cache_dir()
        if older_than_days is None:
            older_than_days = get_plugin_config().media_cache_gc_days

        if older_than_days <= 0:
            return 0

        cutoff = time.time() - older_than_days * 86400
        removed = 0

        for path in cache_dir.iterdir():
            if not path.is_file():
                continue
            if (
                self._media_cache_index_store
                and self._media_cache_index_store.is_index_file(path)
            ):
                continue
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
                    cache_key = self._extract_cache_key_from_path(path)
                    self._remove_media_cache_index_entry(cache_key, path=path)
            except Exception as e:
                logger.debug(f"清理媒体缓存失败：{path} ({e})")

        return removed

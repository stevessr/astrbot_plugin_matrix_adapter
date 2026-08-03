"""Matrix media upload cache-key construction operations."""

import hashlib
from pathlib import Path


class MediaUploadCacheKeysMixin:
    """Build stable keys for in-memory and file-backed uploads."""

    @staticmethod
    def _build_media_upload_cache_key(data: bytes, content_type: str) -> str:
        digest = hashlib.sha256(data).hexdigest()
        return f"{content_type}:{digest}"

    @staticmethod
    def _build_media_upload_cache_key_from_digest(
        digest: str, content_type: str
    ) -> str:
        return f"{content_type}:{digest}"

    @staticmethod
    def _build_media_upload_cache_key_from_file_state(
        file_path: Path,
        content_type: str,
    ) -> str:
        stat_result = file_path.stat()
        identity = (
            f"{file_path.resolve()}:{stat_result.st_dev}:{stat_result.st_ino}:"
            f"{stat_result.st_size}:{stat_result.st_mtime_ns}"
        )
        digest = hashlib.sha256(identity.encode("utf-8", errors="ignore")).hexdigest()
        return f"{content_type}:path:{digest}"

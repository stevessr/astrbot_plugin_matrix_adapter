"""Full-size Matrix media download setup."""

from pathlib import Path

from .......path_utils import quote_path_segment


class MediaDownloadPrimarySetupMixin:
    """Prepare download paths and keys for a media request."""

    async def _prepare_download(
        self,
        mxc_url: str,
        output_path: str | Path | None,
    ):
        """Resolve output path, quoted segments, and cache keys."""
        await self._ensure_session()
        resolved_output_path = Path(output_path) if output_path is not None else None

        server_name, media_id = self._parse_mxc_server_media_id(mxc_url)
        server_path = quote_path_segment(server_name)
        media_path = quote_path_segment(media_id)
        source_key = self._normalize_media_source_key(server_name)
        max_in_memory_bytes = self._get_media_download_max_in_memory_bytes()

        return (
            resolved_output_path,
            server_path,
            media_path,
            source_key,
            max_in_memory_bytes,
        )


__all__ = ["MediaDownloadPrimarySetupMixin"]

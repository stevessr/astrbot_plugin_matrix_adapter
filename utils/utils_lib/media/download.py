"""Download a MXC media URL to a target path via the adapter client."""

import asyncio
from pathlib import Path

from ..reaction import MatrixUtilsReactionMixin


class MatrixUtilsMediaDownloadMixin:
    """Download MXC media via the adapter client into a target path."""

    @staticmethod
    def _ensure_parent_dir(path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _is_existing_nonempty_file(path: Path) -> bool:
        return path.exists() and path.stat().st_size > 0

    @staticmethod
    async def download_media_to_path(
        context,
        mxc_url: str,
        output_path: str | Path,
        *,
        platform_id: str = "",
        allow_thumbnail_fallback: bool = False,
        fallback_to_first: bool = True,
    ) -> Path | None:
        """通过 Matrix 适配器客户端下载 MXC 媒体到指定路径。"""
        if not mxc_url or not str(mxc_url).startswith("mxc://"):
            return None
        resolved_output_path = Path(output_path)
        platform = MatrixUtilsReactionMixin.get_matrix_platform(
            context, platform_id, fallback_to_first=fallback_to_first
        )
        if platform is None:
            return None
        client = getattr(platform, "client", None)
        if client is None or not hasattr(client, "download_file"):
            return None
        await asyncio.to_thread(
            MatrixUtilsMediaDownloadMixin._ensure_parent_dir, resolved_output_path
        )
        await client.download_file(
            mxc_url,
            allow_thumbnail_fallback=allow_thumbnail_fallback,
            output_path=resolved_output_path,
        )
        if not await asyncio.to_thread(
            MatrixUtilsMediaDownloadMixin._is_existing_nonempty_file,
            resolved_output_path,
        ):
            return None
        return resolved_output_path

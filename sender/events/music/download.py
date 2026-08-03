"""Bounded remote music download helpers."""

import uuid
from pathlib import Path

import aiohttp

from ....config.plugin import get_plugin_config

_MUSIC_DOWNLOAD_CHUNK_SIZE = 64 * 1024
_MUSIC_DOWNLOAD_CONNECT_TIMEOUT_SECONDS = 15


def _resolve_music_download_total_timeout_seconds() -> float:
    try:
        timeout_seconds = float(get_plugin_config().http_timeout_seconds)
    except Exception:
        timeout_seconds = 120.0
    timeout_seconds = max(5.0, min(timeout_seconds, 300.0))
    return timeout_seconds


async def _download_music_with_limit(
    url: str, file_path: Path, size_limit: int
) -> None:
    total_timeout_seconds = _resolve_music_download_total_timeout_seconds()
    connect_timeout_seconds = min(
        _MUSIC_DOWNLOAD_CONNECT_TIMEOUT_SECONDS, total_timeout_seconds
    )
    sock_read_timeout_seconds = min(30.0, total_timeout_seconds)
    timeout = aiohttp.ClientTimeout(
        total=total_timeout_seconds,
        connect=connect_timeout_seconds,
        sock_connect=connect_timeout_seconds,
        sock_read=sock_read_timeout_seconds,
    )
    temp_path = file_path.with_name(f".{file_path.name}.{uuid.uuid4().hex}.tmp")
    downloaded_size = 0
    try:
        async with aiohttp.ClientSession(timeout=timeout, trust_env=True) as session:
            async with session.get(
                url,
                headers={"User-Agent": "AstrBot Matrix Adapter/1.0"},
                allow_redirects=True,
            ) as response:
                if response.status != 200:
                    raise RuntimeError(
                        f"Failed to download music: HTTP {response.status}"
                    )

                content_length = response.headers.get("Content-Length")
                if content_length:
                    try:
                        declared_size = int(content_length)
                    except (TypeError, ValueError):
                        declared_size = 0
                    if declared_size > size_limit:
                        raise ValueError(
                            f"Remote music file exceeds size limit ({declared_size} > {size_limit})"
                        )

                with temp_path.open("wb") as output:
                    async for chunk in response.content.iter_chunked(
                        _MUSIC_DOWNLOAD_CHUNK_SIZE
                    ):
                        if not chunk:
                            continue
                        downloaded_size += len(chunk)
                        if downloaded_size > size_limit:
                            raise ValueError(
                                f"Remote music file exceeds size limit ({downloaded_size} > {size_limit})"
                            )
                        output.write(chunk)

        temp_path.replace(file_path)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise

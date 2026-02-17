import mimetypes
import uuid
from pathlib import Path

import aiohttp

from astrbot.api import logger
from astrbot.api.message_components import Music
from astrbot.core.utils.astrbot_path import get_astrbot_data_path

from ...constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES
from .common import send_content

_MUSIC_DOWNLOAD_CHUNK_SIZE = 64 * 1024
_MUSIC_DOWNLOAD_TOTAL_TIMEOUT_SECONDS = 120
_MUSIC_DOWNLOAD_CONNECT_TIMEOUT_SECONDS = 15


async def _download_music_with_limit(url: str, file_path: Path, size_limit: int) -> None:
    timeout = aiohttp.ClientTimeout(
        total=_MUSIC_DOWNLOAD_TOTAL_TIMEOUT_SECONDS,
        connect=_MUSIC_DOWNLOAD_CONNECT_TIMEOUT_SECONDS,
        sock_connect=_MUSIC_DOWNLOAD_CONNECT_TIMEOUT_SECONDS,
        sock_read=30,
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


async def send_music(
    client,
    segment: Music,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    upload_size_limit: int | None = None,
) -> None:
    title = segment.title or ""
    url = segment.url or ""
    audio = segment.audio or ""
    image = segment.image or ""

    if audio:
        size_limit = upload_size_limit or DEFAULT_MAX_UPLOAD_SIZE_BYTES
        if audio.startswith("file:///"):
            file_path = Path(audio[8:])
        elif audio.startswith("http://") or audio.startswith("https://"):
            ext = Path(audio).suffix or ".mp3"
            temp_dir = Path(get_astrbot_data_path()) / "temp"
            temp_dir.mkdir(parents=True, exist_ok=True)
            file_path = temp_dir / f"music_{uuid.uuid4().hex}{ext}"
            await _download_music_with_limit(audio, file_path, size_limit)
        else:
            file_path = Path(audio)

        if not file_path.exists():
            logger.warning(f"音乐文件不存在：{file_path}")
        else:
            filename = file_path.name
            content_type = mimetypes.guess_type(filename)[0] or "audio/mpeg"
            audio_size = file_path.stat().st_size
            if audio_size > size_limit:
                logger.warning(f"音乐文件超过大小限制（{audio_size} > {size_limit}）")
            upload_resp = await client.upload_file_path(
                file_path=file_path,
                content_type=content_type,
                filename=filename,
            )
            content_uri = upload_resp["content_uri"]
            body = title or filename
            content_data = {
                "msgtype": "m.audio",
                "body": body,
                "url": content_uri,
                "info": {"mimetype": content_type, "size": audio_size},
            }
            await send_content(
                client,
                content_data,
                room_id,
                reply_to,
                thread_root,
                use_thread,
                is_encrypted_room,
                e2ee_manager,
            )

            if url or image:
                meta_lines = [line for line in [title, url, image] if line]
                meta_body = "\n".join(meta_lines)
                if meta_body:
                    meta_content = {"msgtype": "m.text", "body": meta_body}
                    await send_content(
                        client,
                        meta_content,
                        room_id,
                        reply_to,
                        thread_root,
                        use_thread,
                        is_encrypted_room,
                        e2ee_manager,
                    )
            return

    lines = [line for line in [title, url, image] if line]
    body = "\n".join(lines) if lines else "[music]"
    content_data = {"msgtype": "m.text", "body": body}
    await send_content(
        client,
        content_data,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
    )

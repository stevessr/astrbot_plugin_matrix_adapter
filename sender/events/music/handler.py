"""Matrix music event sender."""

import mimetypes
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path

from astrbot.api import logger
from astrbot.api.message_components import Music
from astrbot.core.utils.astrbot_path import get_astrbot_data_path

from ....constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES
from ..common import resolve_text_msgtype
from ..common import send_content as _default_send_content
from .download import _download_music_with_limit as _default_download_music

SendContent = Callable[..., Awaitable[dict | None]]
DownloadMusic = Callable[[str, Path, int], Awaitable[None]]
ResolveTextMsgtype = Callable[[bool], str]
GetDataPath = Callable[[], str]


async def _send_music(
    client,
    segment: Music,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    upload_size_limit: int | None = None,
    thread_is_falling_back: bool | None = None,
    use_notice: bool = False,
    *,
    send_content_fn: SendContent | None = None,
    download_music_fn: DownloadMusic | None = None,
    resolve_text_msgtype_fn: ResolveTextMsgtype | None = None,
    get_data_path_fn: GetDataPath | None = None,
    logger_obj=None,
    max_upload_size_bytes: int | None = None,
) -> None:
    sender = send_content_fn or _default_send_content
    downloader = download_music_fn or _default_download_music
    resolve_type = resolve_text_msgtype_fn or resolve_text_msgtype
    data_path = get_data_path_fn or get_astrbot_data_path
    log = logger_obj or logger
    max_size = max_upload_size_bytes or DEFAULT_MAX_UPLOAD_SIZE_BYTES
    title = segment.title or ""
    url = segment.url or ""
    audio = segment.audio or ""
    image = segment.image or ""

    if audio:
        size_limit = upload_size_limit or max_size
        if audio.startswith("file:///"):
            file_path = Path(audio[8:])
        elif audio.startswith("http://") or audio.startswith("https://"):
            ext = Path(audio).suffix or ".mp3"
            temp_dir = Path(data_path()) / "temp"
            temp_dir.mkdir(parents=True, exist_ok=True)
            file_path = temp_dir / f"music_{uuid.uuid4().hex}{ext}"
            await downloader(audio, file_path, size_limit)
        else:
            file_path = Path(audio)

        if not file_path.exists():
            log.warning(f"音乐文件不存在：{file_path}")
        else:
            filename = file_path.name
            content_type = mimetypes.guess_type(filename)[0] or "audio/mpeg"
            audio_size = file_path.stat().st_size
            if audio_size > size_limit:
                log.warning(f"音乐文件超过大小限制（{audio_size} > {size_limit}）")
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
            await sender(
                client,
                content_data,
                room_id,
                reply_to,
                thread_root,
                use_thread,
                is_encrypted_room,
                e2ee_manager,
                thread_is_falling_back=thread_is_falling_back,
            )

            if url or image:
                meta_lines = [line for line in [title, url, image] if line]
                meta_body = "\n".join(meta_lines)
                if meta_body:
                    meta_content = {
                        "msgtype": resolve_type(use_notice),
                        "body": meta_body,
                    }
                    await sender(
                        client,
                        meta_content,
                        room_id,
                        reply_to,
                        thread_root,
                        use_thread,
                        is_encrypted_room,
                        e2ee_manager,
                        thread_is_falling_back=thread_is_falling_back,
                    )
            return

    lines = [line for line in [title, url, image] if line]
    body = "\n".join(lines) if lines else "[music]"
    content_data = {
        "msgtype": resolve_type(use_notice),
        "body": body,
    }
    await sender(
        client,
        content_data,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
        thread_is_falling_back=thread_is_falling_back,
    )

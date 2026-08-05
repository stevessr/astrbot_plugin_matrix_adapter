"""Matrix music event sender."""

from collections.abc import Awaitable, Callable
from pathlib import Path

from astrbot.api import logger
from astrbot.api.message_components import Music
from astrbot.core.utils.astrbot_path import get_astrbot_data_path

from .....constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES
from ...common import resolve_text_msgtype
from ...common import send_content as _default_send_content
from ..download import _download_music_with_limit as _default_download_music
from .audio import _prepare_audio_file
from .send import _send_audio_message

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
        file_path, content_type, audio_size = await _prepare_audio_file(
            segment, upload_size_limit, max_size, data_path, downloader, log
        )
        if file_path is not None:
            await _send_audio_message(
                client,
                segment,
                room_id,
                reply_to,
                thread_root,
                use_thread,
                is_encrypted_room,
                e2ee_manager,
                thread_is_falling_back,
                use_notice,
                file_path,
                content_type,
                audio_size,
                resolve_type,
                sender,
                title,
                url,
                image,
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

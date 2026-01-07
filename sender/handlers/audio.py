import mimetypes
from pathlib import Path

from astrbot.api import logger
from astrbot.api.message_components import Record

from .common import send_content


async def send_audio(
    client,
    segment: Record,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    upload_size_limit: int,
) -> None:
    audio_path = await segment.convert_to_file_path()
    filename = Path(audio_path).name
    with open(audio_path, "rb") as f:
        audio_data = f.read()

    content_type = mimetypes.guess_type(filename)[0] or "audio/ogg"
    audio_size = len(audio_data)
    if audio_size > upload_size_limit:
        logger.warning(
            f"语音大小超过限制（{audio_size} > {upload_size_limit}），上传可能失败"
        )

    upload_resp = await client.upload_file(
        data=audio_data, content_type=content_type, filename=filename
    )

    content_uri = upload_resp["content_uri"]
    content = {
        "msgtype": "m.audio",
        "body": filename,
        "url": content_uri,
        "info": {"mimetype": content_type, "size": audio_size},
    }

    await send_content(
        client,
        content,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
    )

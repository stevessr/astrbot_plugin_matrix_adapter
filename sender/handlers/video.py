import mimetypes
from pathlib import Path

from astrbot.api import logger
from astrbot.api.message_components import Video

from .common import send_content


async def send_video(
    client,
    segment: Video,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    upload_size_limit: int,
) -> None:
    video_path = await segment.convert_to_file_path()
    filename = Path(video_path).name
    with open(video_path, "rb") as f:
        video_data = f.read()

    content_type = mimetypes.guess_type(filename)[0] or "video/mp4"
    video_size = len(video_data)
    if video_size > upload_size_limit:
        logger.warning(
            f"视频大小超过限制（{video_size} > {upload_size_limit}），上传可能失败"
        )

    upload_resp = await client.upload_file(
        data=video_data, content_type=content_type, filename=filename
    )

    content_uri = upload_resp["content_uri"]
    content = {
        "msgtype": "m.video",
        "body": filename,
        "url": content_uri,
        "info": {"mimetype": content_type, "size": video_size},
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

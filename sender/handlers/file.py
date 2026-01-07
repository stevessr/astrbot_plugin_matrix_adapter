from pathlib import Path

from astrbot.api import logger
from astrbot.api.message_components import File

from .common import send_content


async def send_file(
    client,
    segment: File,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
) -> None:
    file_path = await segment.get_file()
    if not file_path:
        logger.warning("文件消息没有可用的文件路径或下载失败")
        return

    with open(file_path, "rb") as f:
        file_data = f.read()

    filename = Path(file_path).name
    content_type = "application/octet-stream"

    upload_resp = await client.upload_file(
        data=file_data, content_type=content_type, filename=filename
    )

    content_uri = upload_resp["content_uri"]
    content = {
        "msgtype": "m.file",
        "body": filename,
        "url": content_uri,
        "filename": filename,
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

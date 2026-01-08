from mimetypes import guess_type
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

    filename = segment.name or Path(file_path).name
    # 根据 Matrix 规范，应该使用正确的 MIME 类型
    content_type = guess_type(filename)[0] or "application/octet-stream"
    file_size = len(file_data)

    upload_resp = await client.upload_file(
        data=file_data, content_type=content_type, filename=filename
    )

    content_uri = upload_resp["content_uri"]
    # 根据 Matrix 规范，m.file 消息应该包含 info 字段
    content = {
        "msgtype": "m.file",
        "body": filename,
        "url": content_uri,
        "filename": filename,
        "info": {
            "mimetype": content_type,
            "size": file_size,
        },
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

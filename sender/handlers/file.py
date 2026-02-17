import asyncio
from mimetypes import guess_type
from pathlib import Path

from astrbot.api import logger
from astrbot.api.message_components import File

from ...constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES
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
    upload_size_limit: int | None = None,
) -> None:
    file_path = await segment.get_file()
    if not file_path:
        logger.warning("文件消息没有可用的文件路径或下载失败")
        return

    file_data = await asyncio.to_thread(Path(file_path).read_bytes)

    filename = segment.name or Path(file_path).name
    # 根据 Matrix 规范，应该使用正确的 MIME 类型
    content_type = guess_type(filename)[0] or "application/octet-stream"
    file_size = len(file_data)
    size_limit = upload_size_limit or DEFAULT_MAX_UPLOAD_SIZE_BYTES
    if file_size > size_limit:
        logger.warning(f"文件大小超过限制（{file_size} > {size_limit}），上传可能失败")

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

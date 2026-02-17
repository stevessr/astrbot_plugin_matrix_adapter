import asyncio
import io
import mimetypes
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.message_components import Image

from ...utils.utils import compress_image_if_needed
from .common import send_content

try:
    from PIL import Image as PILImage
except Exception:
    PILImage = None


async def send_image(
    client,
    segment: Image,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    upload_size_limit: int,
) -> None:
    img_path = await segment.convert_to_file_path()
    image_path = Path(img_path)
    filename = image_path.name

    width, height = None, None
    if PILImage is not None:
        try:
            with PILImage.open(image_path) as img:
                width, height = img.size
        except Exception as e:
            logger.debug(f"无法获取图片尺寸：{e}")

    content_type = mimetypes.guess_type(filename)[0] or "image/png"
    source_size = image_path.stat().st_size
    was_compressed = False
    uploaded_size = source_size

    if source_size > upload_size_limit:
        logger.debug("开始图像压缩（异步执行）...")
        image_data = await asyncio.to_thread(image_path.read_bytes)
        (
            image_data,
            content_type,
            was_compressed,
        ) = await asyncio.get_running_loop().run_in_executor(
            None,
            compress_image_if_needed,
            image_data,
            content_type,
            upload_size_limit,
        )
        logger.debug("图像压缩完成")
        uploaded_size = len(image_data)
    else:
        image_data = None

    if was_compressed:
        filename = image_path.stem + ".jpg"
        if PILImage is not None and image_data is not None:
            try:
                with PILImage.open(io.BytesIO(image_data)) as img:
                    width, height = img.size
            except Exception as e:
                logger.debug(f"无法获取压缩后图片尺寸：{e}")

    if image_data is not None:
        upload_resp = await client.upload_file(
            data=image_data,
            content_type=content_type,
            filename=filename,
        )
    else:
        upload_resp = await client.upload_file_path(
            file_path=image_path,
            content_type=content_type,
            filename=filename,
        )

    content_uri = upload_resp["content_uri"]

    info: dict[str, Any] = {
        "mimetype": content_type,
        "size": uploaded_size,
    }
    if width and height:
        info["w"] = width
        info["h"] = height

    content = {
        "msgtype": "m.image",
        "body": filename,
        "filename": filename,
        "url": content_uri,
        "info": info,
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

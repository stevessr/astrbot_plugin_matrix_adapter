import asyncio
import mimetypes
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.message_components import Image

from ...utils.utils import compress_image_if_needed
from .common import send_content


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
    filename = Path(img_path).name
    with open(img_path, "rb") as f:
        image_data = f.read()

    width, height = None, None
    try:
        import io

        from PIL import Image as PILImage

        with PILImage.open(io.BytesIO(image_data)) as img:
            width, height = img.size
    except Exception as e:
        logger.debug(f"无法获取图片尺寸：{e}")

    content_type = mimetypes.guess_type(filename)[0] or "image/png"

    logger.debug("开始图像压缩（异步执行）...")
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
    if was_compressed:
        filename = Path(filename).stem + ".jpg"
        try:
            with PILImage.open(io.BytesIO(image_data)) as img:
                width, height = img.size
        except Exception as e:
            logger.debug(f"无法获取压缩后图片尺寸：{e}")

    upload_resp = await client.upload_file(
        data=image_data, content_type=content_type, filename=filename
    )

    content_uri = upload_resp["content_uri"]

    info: dict[str, Any] = {
        "mimetype": content_type,
        "size": len(image_data),
    }
    if width and height:
        info["w"] = width
        info["h"] = height

    content = {"msgtype": "m.image", "body": filename, "url": content_uri, "info": info}

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

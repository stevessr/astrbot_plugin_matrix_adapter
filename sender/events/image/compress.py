"""Image compression helpers."""

import asyncio

from astrbot.api import logger

from ....utils.utils import compress_image_if_needed


async def _compress_image(image_path, content_type: str, upload_size_limit: int):
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
    return image_data, content_type, was_compressed

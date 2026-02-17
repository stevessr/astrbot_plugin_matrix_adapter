import asyncio
import mimetypes
from pathlib import Path

from astrbot.api import logger

from .common import send_content


async def send_sticker(
    client,
    segment,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    upload_size_limit: int,
) -> None:
    sticker_data = None
    filename = "sticker.png"
    content_type = segment.info.mimetype or "image/png"
    mxc_url = getattr(segment, "mxc_url", None)

    if mxc_url and mxc_url.startswith("mxc://"):
        content_uri = mxc_url
    else:
        try:
            sticker_path = await segment.convert_to_file_path()
            filename = Path(sticker_path).name
            sticker_data = await asyncio.to_thread(Path(sticker_path).read_bytes)
        except ValueError as e:
            if "MXC URL" in str(e) and segment.url.startswith("mxc://"):
                content_uri = segment.url
            else:
                raise

        if sticker_data:
            width, height = segment.info.width, segment.info.height
            if width is None or height is None:
                try:
                    import io

                    from PIL import Image as PILImage

                    with PILImage.open(io.BytesIO(sticker_data)) as img:
                        width, height = img.size
                except Exception as e:
                    logger.debug(f"无法获取 sticker 尺寸：{e}")

            guessed_type = mimetypes.guess_type(filename)[0]
            if guessed_type:
                content_type = guessed_type

            if len(sticker_data) > upload_size_limit:
                logger.warning(
                    f"Sticker 超过大小限制 ({len(sticker_data)} > {upload_size_limit})"
                )

            upload_resp = await client.upload_file(
                data=sticker_data,
                content_type=content_type,
                filename=filename,
            )
            content_uri = upload_resp["content_uri"]

            segment.mxc_url = content_uri

            if width and height:
                segment.info.width = width
                segment.info.height = height

    content = segment.to_matrix_content(content_uri)

    await send_content(
        client,
        content,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
        msg_type="m.sticker",
    )

"""Image message sending."""

import mimetypes
from pathlib import Path

from astrbot.api.message_components import Image

from ..common import send_content
from .compress import _compress_image
from .content import _build_image_content
from .size import _get_image_dimensions_from_data, _get_image_dimensions_from_path


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
    thread_is_falling_back: bool | None = None,
) -> None:
    img_path = await segment.convert_to_file_path()
    image_path = Path(img_path)
    filename = image_path.name

    width, height = _get_image_dimensions_from_path(image_path)

    content_type = mimetypes.guess_type(filename)[0] or "image/png"
    source_size = image_path.stat().st_size
    was_compressed = False
    uploaded_size = source_size

    if source_size > upload_size_limit:
        (
            image_data,
            content_type,
            was_compressed,
        ) = await _compress_image(image_path, content_type, upload_size_limit)
        uploaded_size = len(image_data)
    else:
        image_data = None

    if was_compressed:
        filename = image_path.stem + ".jpg"
        if image_data is not None:
            width, height = _get_image_dimensions_from_data(image_data)

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

    content = _build_image_content(
        content_uri,
        filename,
        content_type,
        uploaded_size,
        width,
        height,
    )

    await send_content(
        client,
        content,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
        thread_is_falling_back=thread_is_falling_back,
    )

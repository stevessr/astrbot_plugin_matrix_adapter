from astrbot.api import logger
from astrbot.api.message_components import Image, Plain

from .text import append_formatted_text, should_append_caption


async def handle_image(receiver, chain, event, _: str):
    content = event.content or {}
    info_data = content.get("info", {})
    file_info = content.get("file")
    mxc_url = content.get("url")
    filename = content.get("filename") or content.get("body", "image.jpg")
    mimetype = info_data.get("mimetype")

    rendered = False

    if file_info and receiver.client and receiver._should_auto_download_media("m.image"):
        try:
            cache_path = await receiver._download_encrypted_media_file(
                file_info, filename, mimetype
            )
            chain.chain.append(Image.fromFileSystem(str(cache_path)))
            rendered = True
        except Exception as e:
            logger.error(f"Failed to download Matrix encrypted image: {e}")

    if not rendered and mxc_url and receiver.client and receiver._should_auto_download_media("m.image"):
        try:
            cache_path = await receiver._download_media_file(mxc_url, filename, mimetype)
            chain.chain.append(Image.fromFileSystem(str(cache_path)))
            rendered = True
        except Exception as e:
            logger.error(f"Failed to download Matrix image: {e}")

    if not rendered and mxc_url and receiver.mxc_converter and not file_info:
        http_url = receiver.mxc_converter(mxc_url)
        chain.chain.append(Image.fromURL(http_url))
        rendered = True

    if not rendered:
        chain.chain.append(Plain(f"[图片：{event.body}]"))

    if should_append_caption(content, filename):
        append_formatted_text(
            receiver,
            chain,
            content.get("body") or "",
            content,
            allow_command_rewrite=False,
        )

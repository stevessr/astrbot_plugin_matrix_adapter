from astrbot.api import logger
from astrbot.api.message_components import Image, Plain


async def handle_image(receiver, chain, event, _: str):
    mxc_url = event.content.get("url")
    if mxc_url and receiver.client and receiver._should_auto_download_media("m.image"):
        try:
            cache_path = await receiver._download_media_file(
                mxc_url, event.content.get("body", "image.jpg")
            )
            chain.chain.append(Image.fromFileSystem(str(cache_path)))
        except Exception as e:
            logger.error(f"Failed to download Matrix image: {e}")
            chain.chain.append(Plain(f"[图片下载失败：{event.body}]"))
    elif mxc_url and receiver.mxc_converter:
        http_url = receiver.mxc_converter(mxc_url)
        chain.chain.append(Image.fromURL(http_url))
    else:
        chain.chain.append(Plain(f"[图片：{event.body}]"))

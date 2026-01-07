from astrbot.api import logger
from astrbot.api.message_components import File, Plain


async def handle_file(receiver, chain, event, _: str):
    mxc_url = event.content.get("url")
    info_data = event.content.get("info", {})
    filename = event.content.get("body", "file.bin")
    if mxc_url and receiver.client and receiver._should_auto_download_media("m.file"):
        try:
            cache_path = await receiver._download_media_file(
                mxc_url, filename, info_data.get("mimetype")
            )
            chain.chain.append(File(name=filename, file=str(cache_path)))
        except Exception as e:
            logger.error(f"Failed to download Matrix file: {e}")
            chain.chain.append(Plain(f"[文件下载失败：{event.body}]"))
    elif mxc_url and receiver.mxc_converter:
        http_url = receiver.mxc_converter(mxc_url)
        chain.chain.append(File(name=filename, url=http_url))
    else:
        chain.chain.append(Plain(f"[文件：{event.body}]"))

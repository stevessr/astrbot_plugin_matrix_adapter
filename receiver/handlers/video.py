from astrbot.api import logger
from astrbot.api.message_components import Plain, Video


async def handle_video(receiver, chain, event, _: str):
    mxc_url = event.content.get("url")
    info_data = event.content.get("info", {})
    if mxc_url and receiver.client and receiver._should_auto_download_media("m.video"):
        try:
            cache_path = await receiver._download_media_file(
                mxc_url,
                event.content.get("body", "video.mp4"),
                info_data.get("mimetype"),
            )
            chain.chain.append(Video.fromFileSystem(str(cache_path)))
        except Exception as e:
            logger.error(f"Failed to download Matrix video: {e}")
            chain.chain.append(Plain(f"[视频下载失败：{event.body}]"))
    elif mxc_url and receiver.mxc_converter:
        http_url = receiver.mxc_converter(mxc_url)
        try:
            chain.chain.append(Video.fromURL(http_url))
        except Exception:
            chain.chain.append(Plain(f"[视频：{event.body}]"))
    else:
        chain.chain.append(Plain(f"[视频：{event.body}]"))

from astrbot.api import logger
from astrbot.api.message_components import Plain

from ...sticker import Sticker, StickerInfo


async def handle_sticker(receiver, chain, event, _: str):
    mxc_url = event.content.get("url")
    file_info = event.content.get("file")
    info_data = event.content.get("info", {})

    sticker_info = StickerInfo(
        mimetype=info_data.get("mimetype", "image/png"),
        width=info_data.get("w"),
        height=info_data.get("h"),
        size=info_data.get("size"),
        thumbnail_url=info_data.get("thumbnail_url"),
        thumbnail_info=info_data.get("thumbnail_info"),
    )

    if receiver.client and receiver._should_auto_download_media("m.sticker"):
        if file_info:
            try:
                cache_path = await receiver._download_encrypted_media_file(
                    file_info,
                    event.content.get("body", "sticker.png"),
                    sticker_info.mimetype,
                )
                sticker = Sticker(
                    body=event.body,
                    url=f"file:///{cache_path}",
                    info=sticker_info,
                    mxc_url=file_info.get("url", ""),
                )
                chain.chain.append(sticker)
                logger.debug(f"收到 sticker: {event.body}")
                return
            except Exception as e:
                logger.error(f"Failed to download Matrix encrypted sticker: {e}")

        if mxc_url:
            try:
                cache_path = await receiver._download_media_file(
                    mxc_url,
                    event.content.get("body", "sticker.png"),
                    sticker_info.mimetype,
                )
                sticker = Sticker(
                    body=event.body,
                    url=f"file:///{cache_path}",
                    info=sticker_info,
                    mxc_url=mxc_url,
                )
                chain.chain.append(sticker)
                logger.debug(f"收到 sticker: {event.body}")
                return
            except Exception as e:
                logger.error(f"Failed to download Matrix sticker: {e}")

    if mxc_url and not file_info:
        sticker = Sticker(
            body=event.body,
            url=mxc_url,
            info=sticker_info,
            mxc_url=mxc_url,
        )
        chain.chain.append(sticker)
    else:
        chain.chain.append(Plain(f"[贴纸：{event.body}]"))

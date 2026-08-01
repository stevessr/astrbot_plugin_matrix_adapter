from astrbot.api import logger
from astrbot.api.message_components import File, Plain

from ...constants import M_MEDIA_KEY
from .text import append_formatted_text, should_append_caption


def _extract_media_block(content: dict) -> dict:
    media = content.get(M_MEDIA_KEY)
    return media if isinstance(media, dict) else {}


async def handle_file(receiver, chain, event, _: str):
    content = event.content or {}
    media_block = _extract_media_block(content)
    mxc_url = content.get("url") or media_block.get("mxc")
    file_info = content.get("file")
    info_data = content.get("info") or {}
    if not info_data and media_block:
        info_data = {
            "mimetype": media_block.get("mimetype"),
            "size": media_block.get("size"),
        }
    filename = content.get("filename") or content.get("body", "file.bin")
    mimetype = info_data.get("mimetype")
    size_bytes = receiver._extract_media_size(content)
    over_limit = receiver._is_media_over_auto_download_limit(size_bytes)
    if over_limit:
        logger.debug("Skip auto-downloading Matrix file over size limit")

    rendered = False
    if (
        file_info
        and receiver.client
        and receiver._should_auto_download_media("m.file")
        and not over_limit
    ):
        try:
            cache_path = await receiver._download_encrypted_media_file(
                file_info, filename, mimetype
            )
            chain.chain.append(File(name=filename, file=str(cache_path)))
            rendered = True
        except Exception as e:
            logger.error(f"Failed to download Matrix encrypted file: {e}")

    if (
        not rendered
        and mxc_url
        and receiver.client
        and receiver._should_auto_download_media("m.file")
        and not over_limit
    ):
        try:
            cache_path = await receiver._download_media_file(
                mxc_url, filename, mimetype
            )
            chain.chain.append(File(name=filename, file=str(cache_path)))
            rendered = True
        except Exception as e:
            logger.error(f"Failed to download Matrix file: {e}")
            chain.chain.append(Plain(f"[文件下载失败：{event.body}]"))
            rendered = True

    if not rendered and mxc_url and receiver.mxc_converter and not file_info:
        http_url = receiver.mxc_converter(mxc_url)
        chain.chain.append(File(name=filename, url=http_url))
        rendered = True

    if not rendered:
        if over_limit:
            chain.chain.append(Plain(f"[文件过大，已跳过自动下载：{filename}]"))
        else:
            chain.chain.append(Plain(f"[文件：{event.body}]"))

    if should_append_caption(content, filename):
        append_formatted_text(
            receiver,
            chain,
            content.get("body") or "",
            content,
        )

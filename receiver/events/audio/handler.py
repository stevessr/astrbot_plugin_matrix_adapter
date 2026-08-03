"""Inbound Matrix audio event handler."""

from astrbot.api import logger
from astrbot.api.message_components import Plain, Record

from ..text import append_formatted_text, should_append_caption
from .extraction import (
    _extract_audio_file_info,
    _extract_audio_filename,
    _extract_audio_info,
    _extract_audio_size,
    _extract_audio_url,
)


async def handle_audio(receiver, chain, event, _: str):
    content = event.content or {}
    mxc_url = _extract_audio_url(content)
    file_info = _extract_audio_file_info(content)
    info_data = _extract_audio_info(content)
    filename = _extract_audio_filename(content, getattr(event, "body", ""))
    mimetype = info_data.get("mimetype")
    size_bytes = _extract_audio_size(receiver, content, info_data)
    over_limit = receiver._is_media_over_auto_download_limit(size_bytes)
    if over_limit:
        logger.debug("Skip auto-downloading Matrix audio over size limit")

    rendered = False
    if (
        file_info
        and receiver.client
        and receiver._should_auto_download_media("m.audio")
        and not over_limit
    ):
        try:
            cache_path = await receiver._download_encrypted_media_file(
                file_info, filename, mimetype
            )
            chain.chain.append(Record.fromFileSystem(str(cache_path)))
            rendered = True
        except Exception as e:
            logger.error(f"Failed to download Matrix encrypted audio: {e}")

    if (
        not rendered
        and mxc_url
        and receiver.client
        and receiver._should_auto_download_media("m.audio")
        and not over_limit
    ):
        try:
            cache_path = await receiver._download_media_file(
                mxc_url, filename, mimetype
            )
            chain.chain.append(Record.fromFileSystem(str(cache_path)))
            rendered = True
        except Exception as e:
            logger.error(f"Failed to download Matrix audio: {e}")
            chain.chain.append(Plain(f"[语音下载失败：{getattr(event, 'body', '')}]"))
            rendered = True

    if not rendered and mxc_url and receiver.mxc_converter and not file_info:
        http_url = receiver.mxc_converter(mxc_url)
        try:
            chain.chain.append(Record.fromURL(http_url))
            rendered = True
        except Exception:
            chain.chain.append(Plain(f"[语音：{getattr(event, 'body', '')}]"))
            rendered = True

    if not rendered:
        if over_limit:
            chain.chain.append(Plain(f"[语音过大，已跳过自动下载：{filename}]"))
        else:
            chain.chain.append(Plain(f"[语音：{getattr(event, 'body', '')}]"))

    if should_append_caption(content, filename):
        append_formatted_text(
            receiver,
            chain,
            content.get("body") or "",
            content,
        )

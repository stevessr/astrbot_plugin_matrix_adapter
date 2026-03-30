from astrbot.api import logger
from astrbot.api.message_components import Plain, Record

from .text import append_formatted_text, should_append_caption

UNSTABLE_AUDIO_KEY = "org.matrix.msc1767.audio"
UNSTABLE_VOICE_KEY = "org.matrix.msc3245.voice"
UNSTABLE_FILE_KEY = "org.matrix.msc1767.file"


def _extract_unstable_file(content: dict) -> dict:
    unstable_file = content.get(UNSTABLE_FILE_KEY)
    return unstable_file if isinstance(unstable_file, dict) else {}


def _extract_audio_file_info(content: dict) -> dict | None:
    file_info = content.get("file")
    if isinstance(file_info, dict):
        return file_info

    unstable_file = _extract_unstable_file(content)
    encrypted_file = unstable_file.get("file")
    return encrypted_file if isinstance(encrypted_file, dict) else None


def _extract_audio_url(content: dict) -> str | None:
    mxc_url = content.get("url")
    if isinstance(mxc_url, str) and mxc_url:
        return mxc_url

    unstable_file = _extract_unstable_file(content)
    mxc_url = unstable_file.get("url")
    return str(mxc_url) if mxc_url else None


def _extract_audio_info(content: dict) -> dict:
    info_data = content.get("info")
    resolved: dict = dict(info_data) if isinstance(info_data, dict) else {}

    unstable_audio = content.get(UNSTABLE_AUDIO_KEY)
    if isinstance(unstable_audio, dict):
        duration = unstable_audio.get("duration")
        if duration is not None and "duration" not in resolved:
            resolved["duration"] = duration

    unstable_file = _extract_unstable_file(content)
    for key in ("mimetype", "size"):
        value = unstable_file.get(key)
        if value is not None and key not in resolved:
            resolved[key] = value

    return resolved


def _extract_audio_filename(content: dict, event_body: str) -> str:
    filename = content.get("filename")
    if filename:
        return str(filename)

    unstable_file = _extract_unstable_file(content)
    name = unstable_file.get("name")
    if name:
        return str(name)

    return event_body or content.get("body", "audio.mp3")


def _extract_audio_size(receiver, content: dict, info_data: dict) -> int | None:
    size_bytes = receiver._extract_media_size(content)
    if size_bytes is not None:
        return size_bytes

    raw_size = info_data.get("size")
    try:
        size_bytes = int(raw_size)
    except (TypeError, ValueError):
        return None
    return size_bytes if size_bytes >= 0 else None


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
        logger.debug(
            f"Skip auto-downloading Matrix audio over size limit: {filename} ({size_bytes} bytes)"
        )

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
            allow_command_rewrite=False,
        )

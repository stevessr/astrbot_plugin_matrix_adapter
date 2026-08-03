"""Matrix audio content extraction helpers."""

from ....constants import M_MEDIA_KEY, MSC1767_AUDIO_KEY, MSC1767_FILE_KEY

_MEDIA = M_MEDIA_KEY


def _extract_unstable_file(content: dict) -> dict:
    unstable_file = content.get(MSC1767_FILE_KEY)
    return unstable_file if isinstance(unstable_file, dict) else {}


def _extract_media_block(content: dict) -> dict:
    media = content.get(_MEDIA)
    return media if isinstance(media, dict) else {}


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
    if mxc_url:
        return str(mxc_url)

    # MSC3267 fallback to m.media block
    media_block = _extract_media_block(content)
    mxc = media_block.get("mxc")
    return str(mxc) if mxc else None


def _extract_audio_info(content: dict) -> dict:
    info_data = content.get("info")
    resolved: dict = dict(info_data) if isinstance(info_data, dict) else {}

    unstable_audio = content.get(MSC1767_AUDIO_KEY)
    if isinstance(unstable_audio, dict):
        duration = unstable_audio.get("duration")
        if duration is not None and "duration" not in resolved:
            resolved["duration"] = duration

    unstable_file = _extract_unstable_file(content)
    for key in ("mimetype", "size"):
        value = unstable_file.get(key)
        if value is not None and key not in resolved:
            resolved[key] = value

    # MSC3267 fallback to m.media block
    if not resolved:
        media_block = _extract_media_block(content)
        if media_block:
            resolved["mimetype"] = media_block.get("mimetype")
            resolved["size"] = media_block.get("size")
            resolved["duration"] = media_block.get("duration")

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

"""Audio message content construction."""

from typing import Any

from ....constants import (
    M_MEDIA_KEY,
    MSC1767_AUDIO_KEY,
    MSC3245_VOICE_KEY,
    MSC3245_VOICE_V2_KEY,
)


def _build_audio_content(
    filename: str,
    content_uri: str,
    content_type: str,
    audio_size: int,
    info: dict[str, Any],
) -> dict[str, Any]:
    """Build the m.audio message content payload."""
    content: dict[str, Any] = {
        "msgtype": "m.audio",
        "body": filename,
        "filename": filename,
        "url": content_uri,
        "info": info,
        MSC3245_VOICE_KEY: {},
        MSC3245_VOICE_V2_KEY: {},
        # MSC3267 extensible media block
        M_MEDIA_KEY: {
            "mxc": content_uri,
            "mimetype": content_type,
            "size": audio_size,
            **({"duration": info["duration"]} if "duration" in info else {}),
        },
    }
    if isinstance(info.get("duration"), int):
        content[MSC1767_AUDIO_KEY] = {"duration": info["duration"]}
    return content


__all__ = ["_build_audio_content"]

"""Video message content construction."""

from typing import Any

from ....constants import M_MEDIA_KEY


def _build_video_content(
    filename: str,
    content_uri: str,
    content_type: str,
    video_size: int,
    info: dict[str, Any],
) -> dict[str, Any]:
    """Build the m.video message content payload."""
    content: dict[str, Any] = {
        "msgtype": "m.video",
        "body": filename,
        "filename": filename,
        "url": content_uri,
        "info": info,
        # MSC3267 extensible media block
        M_MEDIA_KEY: {
            "mxc": content_uri,
            "mimetype": content_type,
            "size": video_size,
            **(
                {"width": info["w"], "height": info["h"]}
                if "w" in info and "h" in info
                else {}
            ),
            **({"duration": info["duration"]} if "duration" in info else {}),
        },
    }
    return content


__all__ = ["_build_video_content"]

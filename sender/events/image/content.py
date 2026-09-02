"""Image message content building."""

from typing import Any

from ....constants import M_MEDIA_KEY


def _build_image_content(
    content_uri: str,
    filename: str,
    content_type: str,
    uploaded_size: int,
    width,
    height,
    is_animated: bool | None = None,
) -> dict[str, Any]:
    info: dict[str, Any] = {
        "mimetype": content_type,
        "size": uploaded_size,
    }
    if width and height:
        info["w"] = width
        info["h"] = height
    if is_animated is not None:
        # Matrix v1.18 / MSC4230 stable media metadata.
        info["is_animated"] = is_animated

    return {
        "msgtype": "m.image",
        "body": filename,
        "filename": filename,
        "url": content_uri,
        "info": info,
        # MSC3267 extensible media block
        M_MEDIA_KEY: {
            "mxc": content_uri,
            "mimetype": content_type,
            "size": uploaded_size,
            **({"width": width, "height": height} if width and height else {}),
        },
    }

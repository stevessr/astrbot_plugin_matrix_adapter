"""Static settings used by the composed Matrix receiver."""

REPLY_EVENT_FETCH_TIMEOUT_SECONDS = 2.0
QUOTED_MEDIA_DOWNLOAD_TIMEOUT_SECONDS = 2.5
QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY_DEFAULT = 2
IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".svg",
    ".avif",
    ".heic",
    ".heif",
}

__all__ = [
    "REPLY_EVENT_FETCH_TIMEOUT_SECONDS",
    "QUOTED_MEDIA_DOWNLOAD_TIMEOUT_SECONDS",
    "QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY_DEFAULT",
    "IMAGE_EXTENSIONS",
]

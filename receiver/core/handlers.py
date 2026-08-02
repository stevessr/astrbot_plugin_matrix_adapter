"""Message-type dispatch table for the Matrix receiver."""

from ...constants import (
    MSGTYPE_AUDIO,
    MSGTYPE_EMOTE,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_LOCATION,
    MSGTYPE_NOTICE,
    MSGTYPE_REDACTION,
    MSGTYPE_STICKER,
    MSGTYPE_TEXT,
    MSGTYPE_VIDEO,
)
from ..events import (
    handle_audio,
    handle_file,
    handle_image,
    handle_location,
    handle_reaction,
    handle_redaction,
    handle_sticker,
    handle_text,
    handle_video,
)

MESSAGE_TYPE_HANDLERS = {
    MSGTYPE_TEXT: handle_text,
    MSGTYPE_NOTICE: handle_text,
    MSGTYPE_EMOTE: handle_text,
    MSGTYPE_IMAGE: handle_image,
    MSGTYPE_REDACTION: handle_redaction,
    MSGTYPE_STICKER: handle_sticker,
    MSGTYPE_VIDEO: handle_video,
    MSGTYPE_AUDIO: handle_audio,
    MSGTYPE_FILE: handle_file,
    "m.reaction": handle_reaction,
    MSGTYPE_LOCATION: handle_location,
}

__all__ = ["MESSAGE_TYPE_HANDLERS"]

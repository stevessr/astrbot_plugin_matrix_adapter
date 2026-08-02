"""Dispatch individual AstrBot message components to Matrix encoders."""

from astrbot.api import logger
from astrbot.api.message_components import (
    RPS,
    At,
    Contact,
    Dice,
    Face,
    File,
    Forward,
    Image,
    Json,
    Location,
    Music,
    Node,
    Nodes,
    Plain,
    Poke,
    Reply,
    Shake,
    Share,
    Unknown,
    Video,
)

from .....constants import (
    M_POLL,
    M_POLL_KIND_DISCLOSED,
    M_POLL_START,
    MATRIX_HTML_FORMAT,
    MSGTYPE_EMOTE,
)
from ....events import (
    send_at,
    send_audio,
    send_contact,
    send_dice,
    send_file,
    send_image,
    send_location,
    send_music,
    send_plain,
    send_poll,
    send_rps,
    send_shake,
    send_share,
    send_sticker,
    send_video,
)
from ....events.common import send_content
from ....events.record_component import coerce_record_component, is_record_component
from ...content import (
    _fallback_content_for_segment,
    _is_media_security_validation_error,
    _is_poll_component,
    _is_sticker_component,
    _truncate_text,
)
from ..context import SendContext
from .interactive import dispatch_interactive
from .media import dispatch_media
from .special import dispatch_special
from .text import dispatch_text


async def send_segments(context: SendContext) -> int:
    """Dispatch all prepared components and return the successful count."""
    dispatchers = {
        "RPS": RPS,
        "At": At,
        "Contact": Contact,
        "Dice": Dice,
        "Face": Face,
        "File": File,
        "Forward": Forward,
        "Image": Image,
        "Json": Json,
        "Location": Location,
        "Music": Music,
        "Node": Node,
        "Nodes": Nodes,
        "Plain": Plain,
        "Poke": Poke,
        "Reply": Reply,
        "Shake": Shake,
        "Share": Share,
        "Unknown": Unknown,
        "Video": Video,
        "M_POLL": M_POLL,
        "M_POLL_KIND_DISCLOSED": M_POLL_KIND_DISCLOSED,
        "M_POLL_START": M_POLL_START,
        "MATRIX_HTML_FORMAT": MATRIX_HTML_FORMAT,
        "MSGTYPE_EMOTE": MSGTYPE_EMOTE,
        "send_at": send_at,
        "send_audio": send_audio,
        "send_contact": send_contact,
        "send_dice": send_dice,
        "send_file": send_file,
        "send_image": send_image,
        "send_location": send_location,
        "send_music": send_music,
        "send_plain": send_plain,
        "send_poll": send_poll,
        "send_rps": send_rps,
        "send_shake": send_shake,
        "send_share": send_share,
        "send_sticker": send_sticker,
        "send_video": send_video,
        "send_content": send_content,
        "coerce_record_component": coerce_record_component,
        "is_record_component": is_record_component,
        "_fallback_content_for_segment": _fallback_content_for_segment,
        "_is_media_security_validation_error": _is_media_security_validation_error,
        "_is_poll_component": _is_poll_component,
        "_is_sticker_component": _is_sticker_component,
        "_truncate_text": _truncate_text,
    }

    sent_count = 0
    for segment in context.chain_to_send:
        for dispatch in (
            dispatch_text,
            dispatch_media,
            dispatch_interactive,
            dispatch_special,
        ):
            handled, succeeded = await dispatch(context, segment, dispatchers)
            if handled:
                if succeeded:
                    sent_count += 1
                break

    return sent_count


__all__ = [
    "At",
    "Contact",
    "Dice",
    "Face",
    "File",
    "Forward",
    "Image",
    "Json",
    "Location",
    "M_POLL",
    "M_POLL_KIND_DISCLOSED",
    "M_POLL_START",
    "MATRIX_HTML_FORMAT",
    "Music",
    "MSGTYPE_EMOTE",
    "Node",
    "Nodes",
    "Plain",
    "Poke",
    "RPS",
    "Reply",
    "SendContext",
    "Shake",
    "Share",
    "Unknown",
    "Video",
    "coerce_record_component",
    "is_record_component",
    "logger",
    "send_at",
    "send_audio",
    "send_contact",
    "send_content",
    "send_dice",
    "send_file",
    "send_image",
    "send_location",
    "send_music",
    "send_plain",
    "send_poll",
    "send_rps",
    "send_segments",
    "send_shake",
    "send_share",
    "send_sticker",
    "send_video",
]

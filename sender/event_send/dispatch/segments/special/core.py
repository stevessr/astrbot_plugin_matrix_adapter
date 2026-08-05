"""Special, voice, sticker, and compatibility fallback branches."""

from .fallback import _dispatch_fallback
from .poke import _dispatch_poke
from .record import _dispatch_record
from .sticker import _dispatch_sticker
from .video import _dispatch_video


async def dispatch_special(context, segment, dispatchers) -> tuple[bool, bool]:
    """Dispatch video, record, sticker, poke, and fallback components."""
    for _dispatch in (
        _dispatch_video,
        _dispatch_record,
        _dispatch_sticker,
        _dispatch_poke,
        _dispatch_fallback,
    ):
        handled, succeeded = await _dispatch(context, segment, dispatchers)
        if handled:
            return handled, succeeded
    return False, False

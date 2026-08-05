"""Media and basic component dispatch branches."""

from .file import _dispatch_file
from .image import _dispatch_image
from .location import _dispatch_location
from .mention import _dispatch_mention
from .music import _dispatch_music
from .share import _dispatch_share


async def dispatch_media(context, segment, dispatchers) -> tuple[bool, bool]:
    """Dispatch image, mention, file, location, share, and music components."""
    for _dispatch in (
        _dispatch_image,
        _dispatch_mention,
        _dispatch_file,
        _dispatch_location,
        _dispatch_share,
        _dispatch_music,
    ):
        handled, ok = await _dispatch(context, segment, dispatchers)
        if handled:
            return handled, ok
    return False, False

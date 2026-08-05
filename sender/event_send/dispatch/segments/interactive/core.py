"""Poll and interactive component dispatch branches."""

from .contact import _dispatch_contact
from .dice import _dispatch_dice
from .poll import _dispatch_poll
from .rps import _dispatch_rps
from .shake import _dispatch_shake


async def dispatch_interactive(context, segment, dispatchers) -> tuple[bool, bool]:
    """Dispatch polls, contacts, RPS, dice, and shake components."""
    if dispatchers["_is_poll_component"](segment):
        return await _dispatch_poll(context, segment, dispatchers)

    for helper in (_dispatch_contact, _dispatch_rps, _dispatch_dice, _dispatch_shake):
        handled, ok = await helper(context, segment, dispatchers)
        if handled:
            return handled, ok

    return False, False


__all__ = ["dispatch_interactive"]

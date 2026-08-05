"""Poll and interactive component dispatch branches."""

from .contact import _dispatch_contact
from .core import dispatch_interactive
from .dice import _dispatch_dice
from .poll import _dispatch_poll
from .rps import _dispatch_rps
from .shake import _dispatch_shake

__all__ = [
    "_dispatch_contact",
    "_dispatch_dice",
    "_dispatch_poll",
    "_dispatch_rps",
    "_dispatch_shake",
    "dispatch_interactive",
]

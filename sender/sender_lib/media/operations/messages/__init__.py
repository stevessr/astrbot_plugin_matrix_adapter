"""Composable Matrix sender message operations."""

from typing import Any

from astrbot.api.event import MessageChain
from astrbot.api.message_components import Record, Video

from .core import SenderMediaCoreMixin
from .custom import SenderMediaCustomMixin
from .status import SenderMediaStatusMixin


class SenderMediaMessagesMixin(
    SenderMediaCoreMixin,
    SenderMediaCustomMixin,
    SenderMediaStatusMixin,
):
    """Delegate messages, media, reactions, receipts, and typing."""

    pass


for _mixin in (
    SenderMediaCoreMixin,
    SenderMediaCustomMixin,
    SenderMediaStatusMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(SenderMediaMessagesMixin, _method_name, _method)


__all__ = ["Any", "MessageChain", "Record", "SenderMediaMessagesMixin", "Video"]

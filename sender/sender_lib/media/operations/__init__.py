"""Composable Matrix sender media and message operations."""

from typing import Any

from astrbot.api.event import MessageChain
from astrbot.api.message_components import Record, Video

from .messages import SenderMediaMessagesMixin
from .moderation import SenderMediaModerationMixin
from .polls import SenderMediaPollsMixin


class SenderMediaOperationsMixin(
    SenderMediaMessagesMixin,
    SenderMediaPollsMixin,
    SenderMediaModerationMixin,
):
    """Aggregate message, poll, and moderation operations."""

    pass


# Preserve direct methods exposed by the former monolithic mixin.
for _mixin in (
    SenderMediaMessagesMixin,
    SenderMediaPollsMixin,
    SenderMediaModerationMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(SenderMediaOperationsMixin, _method_name, _method)


__all__ = [
    "Any",
    "MessageChain",
    "Record",
    "SenderMediaMessagesMixin",
    "SenderMediaModerationMixin",
    "SenderMediaOperationsMixin",
    "SenderMediaPollsMixin",
    "Video",
]

"""Composable Matrix sender media and message operations."""

from typing import Any  # noqa: F401

from astrbot.api.event import MessageChain  # noqa: F401
from astrbot.api.message_components import Record, Video  # noqa: F401

from .operations import SenderMediaOperationsMixin


class SenderMediaMixin(SenderMediaOperationsMixin):
    """Media, message, poll, and moderation operations for the sender."""

    pass


# Preserve direct method attributes exposed by the former mixin.
for _method_name, _method in SenderMediaOperationsMixin.__dict__.items():
    if callable(_method) and not _method_name.startswith("__"):
        setattr(SenderMediaMixin, _method_name, _method)


__all__ = ["Any", "MessageChain", "Record", "SenderMediaMixin", "Video"]

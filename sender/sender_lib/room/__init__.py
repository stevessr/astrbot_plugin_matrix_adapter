"""Composable Matrix sender room operations."""

from typing import Any  # noqa: F401

from .operations import SenderRoomOperationsMixin


class SenderRoomMixin(SenderRoomOperationsMixin):
    """Room management and moderation operations for the sender."""

    pass


# Preserve direct method attributes exposed by the former mixin.
for _method_name, _method in SenderRoomOperationsMixin.__dict__.items():
    if callable(_method) and not _method_name.startswith("__"):
        setattr(SenderRoomMixin, _method_name, _method)


__all__ = ["Any", "SenderRoomMixin"]

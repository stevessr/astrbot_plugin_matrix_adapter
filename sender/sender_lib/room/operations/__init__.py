"""Composable Matrix sender room operations."""

from typing import Any

from .lifecycle import SenderRoomLifecycleMixin
from .metadata import SenderRoomMetadataMixin
from .moderation import SenderRoomModerationMixin
from .queries import SenderRoomQueriesMixin


class SenderRoomOperationsMixin(
    SenderRoomLifecycleMixin,
    SenderRoomQueriesMixin,
    SenderRoomModerationMixin,
    SenderRoomMetadataMixin,
):
    """Aggregates room lifecycle, query, moderation, and metadata operations."""

    pass


# Preserve direct method attributes exposed by the former monolithic mixin.
for _mixin in (
    SenderRoomLifecycleMixin,
    SenderRoomQueriesMixin,
    SenderRoomModerationMixin,
    SenderRoomMetadataMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(SenderRoomOperationsMixin, _method_name, _method)


__all__ = [
    "Any",
    "SenderRoomLifecycleMixin",
    "SenderRoomMetadataMixin",
    "SenderRoomModerationMixin",
    "SenderRoomOperationsMixin",
    "SenderRoomQueriesMixin",
]

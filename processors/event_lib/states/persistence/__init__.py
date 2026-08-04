"""Room state persistence and in-memory application handlers."""

from .apply import MatrixEventProcessorApplyMixin
from .persist import MatrixEventProcessorPersistMixin
from .types import (
    LIVE_MESSAGING_STATE_EVENT_TYPES,
    VISIBLE_ROOM_STATE_EVENT_TYPES,
    _is_room_state_event_type,
)


class MatrixEventProcessorPersistenceMixin(
    MatrixEventProcessorPersistMixin,
    MatrixEventProcessorApplyMixin,
):
    """Persist room state and apply state events to room objects."""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    MatrixEventProcessorPersistMixin,
    MatrixEventProcessorApplyMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod, property)) or callable(
            _method
        ):
            setattr(MatrixEventProcessorPersistenceMixin, _name, _method)

__all__ = [
    "LIVE_MESSAGING_STATE_EVENT_TYPES",
    "MatrixEventProcessorPersistenceMixin",
    "VISIBLE_ROOM_STATE_EVENT_TYPES",
    "_is_room_state_event_type",
]

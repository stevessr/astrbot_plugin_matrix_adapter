"""Composable Matrix reaction utility operations."""

from astrbot.api import logger

from .events import MatrixUtilsReactionEventsMixin
from .keys import MatrixUtilsReactionKeysMixin
from .platform import MatrixUtilsReactionPlatformMixin
from .send import MatrixUtilsReactionSendMixin


class MatrixUtilsReactionMixin(
    MatrixUtilsReactionPlatformMixin,
    MatrixUtilsReactionKeysMixin,
    MatrixUtilsReactionEventsMixin,
    MatrixUtilsReactionSendMixin,
):
    """Aggregates platform, key, event, and sending reaction helpers."""

    pass


# Preserve direct staticmethod attributes exposed by the former monolithic mixin.
for _mixin in (
    MatrixUtilsReactionPlatformMixin,
    MatrixUtilsReactionKeysMixin,
    MatrixUtilsReactionEventsMixin,
    MatrixUtilsReactionSendMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixUtilsReactionMixin, _method_name, _method)


__all__ = [
    "MatrixUtilsReactionEventsMixin",
    "MatrixUtilsReactionKeysMixin",
    "MatrixUtilsReactionMixin",
    "MatrixUtilsReactionPlatformMixin",
    "MatrixUtilsReactionSendMixin",
    "logger",
]

"""
Matrix Event Processor - /sync stream handlers.
"""

from .account import MatrixEventProcessorStreamsAccountMixin
from .devices import MatrixEventProcessorStreamsDevicesMixin
from .ephemeral import MatrixEventProcessorStreamsEphemeralMixin
from .leave import MatrixEventProcessorStreamsLeaveMixin


class MatrixEventProcessorStreams(
    MatrixEventProcessorStreamsAccountMixin,
    MatrixEventProcessorStreamsEphemeralMixin,
    MatrixEventProcessorStreamsDevicesMixin,
    MatrixEventProcessorStreamsLeaveMixin,
):
    """Mixin for /sync stream processing."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixEventProcessorStreamsAccountMixin,
    MatrixEventProcessorStreamsEphemeralMixin,
    MatrixEventProcessorStreamsDevicesMixin,
    MatrixEventProcessorStreamsLeaveMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixEventProcessorStreams, _method_name, _method)


__all__ = ["MatrixEventProcessorStreams"]

"""Live message payload construction and delivery."""

from .build import MatrixPlatformEventMessagesPayloadBuildMixin
from .core import MatrixPlatformEventMessagesPayloadOrchestratorMixin
from .meta import MatrixPlatformEventMessagesPayloadMetaMixin
from .send import MatrixPlatformEventMessagesPayloadSendMixin


class MatrixPlatformEventMessagesPayloadMixin(
    MatrixPlatformEventMessagesPayloadOrchestratorMixin,
    MatrixPlatformEventMessagesPayloadBuildMixin,
    MatrixPlatformEventMessagesPayloadMetaMixin,
    MatrixPlatformEventMessagesPayloadSendMixin,
):
    """Build and send single live-message payloads."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixPlatformEventMessagesPayloadOrchestratorMixin,
    MatrixPlatformEventMessagesPayloadBuildMixin,
    MatrixPlatformEventMessagesPayloadMetaMixin,
    MatrixPlatformEventMessagesPayloadSendMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixPlatformEventMessagesPayloadMixin, _method_name, _method)


__all__ = [
    "MatrixPlatformEventMessagesPayloadMixin",
    "MatrixPlatformEventMessagesPayloadOrchestratorMixin",
    "MatrixPlatformEventMessagesPayloadBuildMixin",
    "MatrixPlatformEventMessagesPayloadMetaMixin",
    "MatrixPlatformEventMessagesPayloadSendMixin",
]

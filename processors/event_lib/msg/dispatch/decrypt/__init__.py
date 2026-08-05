"""Message event decryption and verification routing."""

from .core import MatrixEventProcessorMessagesDecryptOrchestratorMixin
from .guard import MatrixEventProcessorMessagesDecryptGuardMixin
from .verify import MatrixEventProcessorMessagesDecryptVerifyMixin


class MatrixEventProcessorMessagesDecryptMixin(
    MatrixEventProcessorMessagesDecryptOrchestratorMixin,
    MatrixEventProcessorMessagesDecryptVerifyMixin,
    MatrixEventProcessorMessagesDecryptGuardMixin,
):
    """Decrypt encrypted message events and route verification events."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixEventProcessorMessagesDecryptOrchestratorMixin,
    MatrixEventProcessorMessagesDecryptVerifyMixin,
    MatrixEventProcessorMessagesDecryptGuardMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixEventProcessorMessagesDecryptMixin, _method_name, _method)


__all__ = [
    "MatrixEventProcessorMessagesDecryptMixin",
    "MatrixEventProcessorMessagesDecryptOrchestratorMixin",
    "MatrixEventProcessorMessagesDecryptVerifyMixin",
    "MatrixEventProcessorMessagesDecryptGuardMixin",
]

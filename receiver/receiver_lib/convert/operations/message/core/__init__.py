"""Matrix message event conversion orchestrator."""

from .core import MatrixReceiverMessageConvertOrchestratorMixin
from .parse import MatrixReceiverMessageConvertParseMixin
from .sender import MatrixReceiverMessageConvertSenderMixin
from .type import MatrixReceiverMessageConvertTypeMixin


class MatrixReceiverMessageConvertCoreMixin(
    MatrixReceiverMessageConvertOrchestratorMixin,
    MatrixReceiverMessageConvertParseMixin,
    MatrixReceiverMessageConvertSenderMixin,
    MatrixReceiverMessageConvertTypeMixin,
):
    """Convert Matrix message events to AstrBot messages."""


# Preserve direct method attributes expected by parent-package __dict__ lookups.
for _mixin in (
    MatrixReceiverMessageConvertOrchestratorMixin,
    MatrixReceiverMessageConvertParseMixin,
    MatrixReceiverMessageConvertSenderMixin,
    MatrixReceiverMessageConvertTypeMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixReceiverMessageConvertCoreMixin, _method_name, _method)


__all__ = [
    "MatrixReceiverMessageConvertCoreMixin",
    "MatrixReceiverMessageConvertOrchestratorMixin",
    "MatrixReceiverMessageConvertParseMixin",
    "MatrixReceiverMessageConvertSenderMixin",
    "MatrixReceiverMessageConvertTypeMixin",
]

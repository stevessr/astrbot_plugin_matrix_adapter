"""Megolm inbound session import operations.

Public symbols re-exported for backward compatibility.
"""

from .core import OlmMachineMegolmInboundImportCoreMixin
from .provenance import OlmMachineMegolmInboundProvenanceMixin


class OlmMachineMegolmInboundImportMixin(
    OlmMachineMegolmInboundImportCoreMixin,
    OlmMachineMegolmInboundProvenanceMixin,
):
    """Import Megolm inbound sessions."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    OlmMachineMegolmInboundImportCoreMixin,
    OlmMachineMegolmInboundProvenanceMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(OlmMachineMegolmInboundImportMixin, _method_name, _method)


__all__ = [
    "OlmMachineMegolmInboundImportCoreMixin",
    "OlmMachineMegolmInboundImportMixin",
    "OlmMachineMegolmInboundProvenanceMixin",
]

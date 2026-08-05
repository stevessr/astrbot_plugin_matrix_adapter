"""Megolm inbound session import orchestration."""

from .convert import OlmMachineMegolmInboundImportConvertMixin
from .core import OlmMachineMegolmInboundImportFlowMixin
from .existing import OlmMachineMegolmInboundImportExistingMixin
from .persist import OlmMachineMegolmInboundImportPersistMixin


class OlmMachineMegolmInboundImportCoreMixin(OlmMachineMegolmInboundImportFlowMixin):
    """Import Megolm inbound sessions and persist them."""

    pass


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    OlmMachineMegolmInboundImportFlowMixin,
    OlmMachineMegolmInboundImportConvertMixin,
    OlmMachineMegolmInboundImportExistingMixin,
    OlmMachineMegolmInboundImportPersistMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if _method_name.startswith("__"):
            continue
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(
                OlmMachineMegolmInboundImportCoreMixin,
                _method_name,
                _method,
            )


__all__ = [
    "OlmMachineMegolmInboundImportConvertMixin",
    "OlmMachineMegolmInboundImportCoreMixin",
    "OlmMachineMegolmInboundImportExistingMixin",
    "OlmMachineMegolmInboundImportFlowMixin",
    "OlmMachineMegolmInboundImportPersistMixin",
]

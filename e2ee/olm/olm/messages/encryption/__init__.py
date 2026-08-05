"""Olm message encryption and Matrix envelope construction."""

from .core import OlmMachineMessageEncryptionOrchestratorMixin
from .envelope import OlmMachineMessageEnvelopeMixin
from .session import OlmMachineMessageEncryptSessionMixin


class OlmMachineMessageEncryptionMixin(
    OlmMachineMessageEncryptionOrchestratorMixin,
    OlmMachineMessageEncryptSessionMixin,
    OlmMachineMessageEnvelopeMixin,
):
    """Encrypt Olm content and build the Matrix protocol envelope."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    OlmMachineMessageEncryptionOrchestratorMixin,
    OlmMachineMessageEncryptSessionMixin,
    OlmMachineMessageEnvelopeMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(OlmMachineMessageEncryptionMixin, _method_name, _method)


__all__ = [
    "OlmMachineMessageEncryptionMixin",
    "OlmMachineMessageEncryptionOrchestratorMixin",
    "OlmMachineMessageEncryptSessionMixin",
    "OlmMachineMessageEnvelopeMixin",
]

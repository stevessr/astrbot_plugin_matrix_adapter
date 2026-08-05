"""Olm to-device event decryption and session re-request."""

from .ciphertext import E2EEManagerDecryptOlmCiphertextMixin
from .core import E2EEManagerDecryptOlmOrchestratorMixin
from .parse import E2EEManagerDecryptOlmParseMixin


class E2EEManagerDecryptOlmMixin(
    E2EEManagerDecryptOlmOrchestratorMixin,
    E2EEManagerDecryptOlmCiphertextMixin,
    E2EEManagerDecryptOlmParseMixin,
):
    """Decrypt m.room.encrypted Olm payloads addressed to this device."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerDecryptOlmOrchestratorMixin,
    E2EEManagerDecryptOlmCiphertextMixin,
    E2EEManagerDecryptOlmParseMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerDecryptOlmMixin, _method_name, _method)


__all__ = [
    "E2EEManagerDecryptOlmCiphertextMixin",
    "E2EEManagerDecryptOlmMixin",
    "E2EEManagerDecryptOlmOrchestratorMixin",
    "E2EEManagerDecryptOlmParseMixin",
]

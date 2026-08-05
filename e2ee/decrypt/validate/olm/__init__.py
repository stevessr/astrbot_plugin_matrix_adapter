"""Mandatory Olm plaintext validation."""

from .claims import E2EEManagerDecryptOlmClaimMixin
from .core import E2EEManagerDecryptOlmValidateOrchestratorMixin
from .device import E2EEManagerDecryptOlmDeviceMixin
from .legacy import E2EEManagerDecryptOlmLegacyMixin


class E2EEManagerDecryptOlmValidateMixin(
    E2EEManagerDecryptOlmValidateOrchestratorMixin,
    E2EEManagerDecryptOlmClaimMixin,
    E2EEManagerDecryptOlmDeviceMixin,
    E2EEManagerDecryptOlmLegacyMixin,
):
    """Validate incoming Olm plaintext against the sender's device keys."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerDecryptOlmValidateOrchestratorMixin,
    E2EEManagerDecryptOlmClaimMixin,
    E2EEManagerDecryptOlmDeviceMixin,
    E2EEManagerDecryptOlmLegacyMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerDecryptOlmValidateMixin, _method_name, _method)


__all__ = [
    "E2EEManagerDecryptOlmClaimMixin",
    "E2EEManagerDecryptOlmDeviceMixin",
    "E2EEManagerDecryptOlmLegacyMixin",
    "E2EEManagerDecryptOlmValidateMixin",
    "E2EEManagerDecryptOlmValidateOrchestratorMixin",
]

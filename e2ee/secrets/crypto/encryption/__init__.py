"""Olm to-device encryption helpers for secret sharing."""

from .core import E2EEManagerSecretsEncryptionCoreMixin
from .session import E2EEManagerSecretsEncryptionSessionMixin


class E2EEManagerSecretsEncryptionMixin(
    E2EEManagerSecretsEncryptionCoreMixin,
    E2EEManagerSecretsEncryptionSessionMixin,
):
    """to-device Olm 加密相关能力。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    E2EEManagerSecretsEncryptionCoreMixin,
    E2EEManagerSecretsEncryptionSessionMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerSecretsEncryptionMixin, _name, _method)

__all__ = ["E2EEManagerSecretsEncryptionMixin"]

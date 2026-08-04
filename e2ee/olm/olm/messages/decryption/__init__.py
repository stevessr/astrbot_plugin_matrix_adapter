"""Olm message decryption and inbound-session recovery.

Public symbols re-exported for backward compatibility.
"""

from .core import OlmMachineMessageDecryptionCoreMixin
from .prekey import OlmMachineMessageDecryptionPreKeyMixin
from .sessions import OlmMachineMessageDecryptionSessionsMixin


class OlmMachineMessageDecryptionMixin(
    OlmMachineMessageDecryptionCoreMixin,
    OlmMachineMessageDecryptionSessionsMixin,
    OlmMachineMessageDecryptionPreKeyMixin,
):
    """解密 Olm 消息并从 PreKey 消息创建入站会话。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    OlmMachineMessageDecryptionCoreMixin,
    OlmMachineMessageDecryptionSessionsMixin,
    OlmMachineMessageDecryptionPreKeyMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(OlmMachineMessageDecryptionMixin, _method_name, _method)


__all__ = [
    "OlmMachineMessageDecryptionCoreMixin",
    "OlmMachineMessageDecryptionMixin",
    "OlmMachineMessageDecryptionPreKeyMixin",
    "OlmMachineMessageDecryptionSessionsMixin",
]

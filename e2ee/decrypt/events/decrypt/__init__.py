"""Encrypted-event decryption split by algorithm.

Public symbols re-exported for backward compatibility.
"""

from .core import E2EEManagerDecryptEventCoreMixin
from .megolm import E2EEManagerDecryptMegolmMixin
from .olm import E2EEManagerDecryptOlmMixin


class E2EEManagerDecryptEventMixin(
    E2EEManagerDecryptEventCoreMixin,
    E2EEManagerDecryptMegolmMixin,
    E2EEManagerDecryptOlmMixin,
):
    """解密加密事件"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerDecryptEventCoreMixin,
    E2EEManagerDecryptMegolmMixin,
    E2EEManagerDecryptOlmMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerDecryptEventMixin, _method_name, _method)


__all__ = [
    "E2EEManagerDecryptEventCoreMixin",
    "E2EEManagerDecryptEventMixin",
    "E2EEManagerDecryptMegolmMixin",
    "E2EEManagerDecryptOlmMixin",
]

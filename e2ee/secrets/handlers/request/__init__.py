"""Secret request handling.

Public symbols re-exported for backward compatibility.
"""

from .core import E2EEManagerSecretsRequestCoreMixin
from .sharing import E2EEManagerSecretsSharingMixin


class E2EEManagerSecretsRequestMixin(
    E2EEManagerSecretsRequestCoreMixin,
    E2EEManagerSecretsSharingMixin,
):
    """处理设备间秘密共享请求，并读取本地可共享秘密。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerSecretsRequestCoreMixin,
    E2EEManagerSecretsSharingMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerSecretsRequestMixin, _method_name, _method)


__all__ = [
    "E2EEManagerSecretsRequestCoreMixin",
    "E2EEManagerSecretsRequestMixin",
    "E2EEManagerSecretsSharingMixin",
]

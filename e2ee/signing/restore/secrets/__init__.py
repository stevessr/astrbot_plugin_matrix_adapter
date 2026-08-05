"""Secret Storage recovery and persistence for cross-signing keys."""

from .read import CrossSigningRestoreSecretsReadMixin
from .write import CrossSigningRestoreSecretsWriteMixin


class CrossSigningRestoreSecretsMixin(
    CrossSigningRestoreSecretsReadMixin,
    CrossSigningRestoreSecretsWriteMixin,
):
    """从 Secret Storage 恢复并写入交叉签名私钥。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    CrossSigningRestoreSecretsReadMixin,
    CrossSigningRestoreSecretsWriteMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(CrossSigningRestoreSecretsMixin, _method_name, _method)


__all__ = [
    "CrossSigningRestoreSecretsMixin",
    "CrossSigningRestoreSecretsReadMixin",
    "CrossSigningRestoreSecretsWriteMixin",
]

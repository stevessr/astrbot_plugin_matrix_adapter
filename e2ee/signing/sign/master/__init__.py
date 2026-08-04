"""Master-key device-signing operations for cross-signing."""

from .core import CrossSigningMasterSignCoreMixin
from .fetch import CrossSigningMasterSignFetchMixin


class CrossSigningMasterSignMixin(
    CrossSigningMasterSignCoreMixin,
    CrossSigningMasterSignFetchMixin,
):
    """为当前账号 master key 上传当前设备签名。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    CrossSigningMasterSignCoreMixin,
    CrossSigningMasterSignFetchMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(CrossSigningMasterSignMixin, _name, _method)

__all__ = ["CrossSigningMasterSignMixin"]

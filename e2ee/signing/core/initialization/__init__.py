"""Cross-signing construction and initialization lifecycle.

Public symbols re-exported for backward compatibility.
"""

from .flow import CrossSigningCoreFlowMixin
from .setup import CrossSigningCoreSetupMixin


class CrossSigningCoreInitializationMixin(
    CrossSigningCoreSetupMixin,
    CrossSigningCoreFlowMixin,
):
    """初始化交叉签名并准备本地持久化状态。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    CrossSigningCoreSetupMixin,
    CrossSigningCoreFlowMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(CrossSigningCoreInitializationMixin, _method_name, _method)


__all__ = [
    "CrossSigningCoreFlowMixin",
    "CrossSigningCoreInitializationMixin",
    "CrossSigningCoreSetupMixin",
]

"""Room-message encryption and rotation orchestration.

Public symbols re-exported for backward compatibility.
"""

from .core import E2EEManagerSessionEncryptMessageCoreMixin
from .rotation import E2EEManagerSessionEncryptMessageRotationMixin


class E2EEManagerSessionEncryptMessageMixin(
    E2EEManagerSessionEncryptMessageCoreMixin,
    E2EEManagerSessionEncryptMessageRotationMixin,
):
    """加密房间消息并在必要时轮换出站会话。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerSessionEncryptMessageCoreMixin,
    E2EEManagerSessionEncryptMessageRotationMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerSessionEncryptMessageMixin, _method_name, _method)


__all__ = [
    "E2EEManagerSessionEncryptMessageCoreMixin",
    "E2EEManagerSessionEncryptMessageMixin",
    "E2EEManagerSessionEncryptMessageRotationMixin",
]

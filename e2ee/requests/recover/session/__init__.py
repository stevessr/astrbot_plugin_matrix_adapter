"""Recovery of Olm sessions after a missing-session decryption failure.

Public symbols re-exported for backward compatibility.
"""

from .core import E2EEManagerRequestsSessionCoreMixin
from .establish import E2EEManagerRequestsSessionEstablishMixin


class E2EEManagerRequestsSessionMixin(
    E2EEManagerRequestsSessionCoreMixin,
    E2EEManagerRequestsSessionEstablishMixin,
):
    """主动建立新的 Olm 会话并跟踪恢复节流。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerRequestsSessionCoreMixin,
    E2EEManagerRequestsSessionEstablishMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerRequestsSessionMixin, _method_name, _method)


__all__ = [
    "E2EEManagerRequestsSessionCoreMixin",
    "E2EEManagerRequestsSessionEstablishMixin",
    "E2EEManagerRequestsSessionMixin",
]

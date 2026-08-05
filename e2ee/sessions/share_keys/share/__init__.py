"""Room-key sharing entry points and per-session locking."""

from .existing import E2EEManagerSessionShareKeysExistingMixin
from .lock import E2EEManagerSessionShareKeysShareOrchestratorMixin
from .members import E2EEManagerSessionShareKeysMembersMixin
from .session import E2EEManagerSessionShareKeysSessionMixin


class E2EEManagerSessionShareKeysEntryMixin(
    E2EEManagerSessionShareKeysShareOrchestratorMixin,
    E2EEManagerSessionShareKeysExistingMixin,
    E2EEManagerSessionShareKeysMembersMixin,
    E2EEManagerSessionShareKeysSessionMixin,
):
    """为选定成员准备并锁定房间密钥分发。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerSessionShareKeysShareOrchestratorMixin,
    E2EEManagerSessionShareKeysExistingMixin,
    E2EEManagerSessionShareKeysMembersMixin,
    E2EEManagerSessionShareKeysSessionMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerSessionShareKeysEntryMixin, _method_name, _method)


__all__ = [
    "E2EEManagerSessionShareKeysEntryMixin",
    "E2EEManagerSessionShareKeysExistingMixin",
    "E2EEManagerSessionShareKeysMembersMixin",
    "E2EEManagerSessionShareKeysSessionMixin",
    "E2EEManagerSessionShareKeysShareOrchestratorMixin",
]

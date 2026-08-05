"""In-room verification event routing and session ownership checks."""

from .core import SASVerificationRoomEventDispatchOrchestratorMixin
from .dispatch import SASVerificationRoomEventDispatchRouteMixin
from .relates import SASVerificationRoomEventDispatchRelatesMixin
from .session import SASVerificationRoomEventDispatchSessionMixin


class SASVerificationRoomEventDispatchCoreMixin(
    SASVerificationRoomEventDispatchOrchestratorMixin,
    SASVerificationRoomEventDispatchRouteMixin,
    SASVerificationRoomEventDispatchRelatesMixin,
    SASVerificationRoomEventDispatchSessionMixin,
):
    """解析房间内事件关系、处理设备接管并路由事件。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    SASVerificationRoomEventDispatchOrchestratorMixin,
    SASVerificationRoomEventDispatchRouteMixin,
    SASVerificationRoomEventDispatchRelatesMixin,
    SASVerificationRoomEventDispatchSessionMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationRoomEventDispatchCoreMixin, _method_name, _method)


__all__ = [
    "SASVerificationRoomEventDispatchCoreMixin",
    "SASVerificationRoomEventDispatchOrchestratorMixin",
    "SASVerificationRoomEventDispatchRelatesMixin",
    "SASVerificationRoomEventDispatchRouteMixin",
    "SASVerificationRoomEventDispatchSessionMixin",
]

"""Room-key withheld notices and m.no_olm recovery signaling."""

from .core import E2EEManagerRequestsWithheldCoreMixin
from .receive import E2EEManagerRequestsWithheldReceiveMixin
from .signal import E2EEManagerRequestsWithheldSignalMixin


class E2EEManagerRequestsWithheldMixin(
    E2EEManagerRequestsWithheldCoreMixin,
    E2EEManagerRequestsWithheldSignalMixin,
    E2EEManagerRequestsWithheldReceiveMixin,
):
    """发送和处理 Matrix room-key withheld 事件。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    E2EEManagerRequestsWithheldCoreMixin,
    E2EEManagerRequestsWithheldSignalMixin,
    E2EEManagerRequestsWithheldReceiveMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerRequestsWithheldMixin, _name, _method)

__all__ = ["E2EEManagerRequestsWithheldMixin"]

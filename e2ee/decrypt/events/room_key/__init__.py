"""m.room_key event handling.

Public symbols re-exported for backward compatibility.
"""

from .claims import E2EEManagerDecryptRoomKeyClaimsMixin
from .core import E2EEManagerDecryptRoomKeyCoreMixin
from .provenance import E2EEManagerDecryptRoomKeyProvenanceMixin


class E2EEManagerDecryptRoomKeyMixin(
    E2EEManagerDecryptRoomKeyCoreMixin,
    E2EEManagerDecryptRoomKeyProvenanceMixin,
    E2EEManagerDecryptRoomKeyClaimsMixin,
):
    """Import received Megolm room keys."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerDecryptRoomKeyCoreMixin,
    E2EEManagerDecryptRoomKeyProvenanceMixin,
    E2EEManagerDecryptRoomKeyClaimsMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerDecryptRoomKeyMixin, _method_name, _method)


__all__ = [
    "E2EEManagerDecryptRoomKeyClaimsMixin",
    "E2EEManagerDecryptRoomKeyCoreMixin",
    "E2EEManagerDecryptRoomKeyMixin",
    "E2EEManagerDecryptRoomKeyProvenanceMixin",
]

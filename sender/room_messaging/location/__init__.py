"""Live-location beacon sender extensions."""

from .beacon import SenderLocationBeaconMixin
from .beacon_info import SenderLocationBeaconInfoMixin


class SenderLocationMixin(
    SenderLocationBeaconInfoMixin,
    SenderLocationBeaconMixin,
):
    """Live-location beacon sender extensions."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    SenderLocationBeaconInfoMixin,
    SenderLocationBeaconMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SenderLocationMixin, _method_name, _method)


__all__ = ["SenderLocationMixin"]

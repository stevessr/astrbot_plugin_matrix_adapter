"""Composable Matrix verification device-message sender."""

from ..constants import VODOZEMAC_SAS_AVAILABLE
from .handshake import SASVerificationSendDeviceHandshakeMixin
from .messages import SASVerificationSendDeviceMessagesMixin
from .negotiation import SASVerificationSendDeviceNegotiationMixin


class SASVerificationSendDeviceMixin(
    SASVerificationSendDeviceNegotiationMixin,
    SASVerificationSendDeviceHandshakeMixin,
    SASVerificationSendDeviceMessagesMixin,
):
    """发送 Matrix 设备验证握手、身份 MAC 和控制消息。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _method_name in (
    "_get_supported_verification_methods",
    "_peer_device_trusts_own_master_key",
    "_get_verification_keys_to_mac",
    "_send_ready",
    "_send_start",
    "_send_accept",
    "_send_key",
    "_send_mac",
    "_send_done",
    "_send_cancel",
    "_send_to_device",
):
    for _mixin in (
        SASVerificationSendDeviceNegotiationMixin,
        SASVerificationSendDeviceHandshakeMixin,
        SASVerificationSendDeviceMessagesMixin,
    ):
        if hasattr(_mixin, _method_name):
            setattr(
                SASVerificationSendDeviceMixin,
                _method_name,
                getattr(_mixin, _method_name),
            )
            break

for _method_name in ("_normalize_algorithm_values", "_pick_algorithm"):
    setattr(
        SASVerificationSendDeviceMixin,
        _method_name,
        staticmethod(getattr(SASVerificationSendDeviceNegotiationMixin, _method_name)),
    )

__all__ = [
    "SASVerificationSendDeviceHandshakeMixin",
    "SASVerificationSendDeviceMessagesMixin",
    "SASVerificationSendDeviceMixin",
    "VODOZEMAC_SAS_AVAILABLE",
    "SASVerificationSendDeviceNegotiationMixin",
]

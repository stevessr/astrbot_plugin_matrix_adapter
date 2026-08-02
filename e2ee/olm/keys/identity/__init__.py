"""Composable Olm identity and device-key mixins."""

from typing import Any

from .....constants import MEGOLM_ALGO, OLM_ALGO
from ....verification.crypto_utils import _canonical_json
from .device import OlmMachineKeyDeviceSerializationMixin
from .keys import OlmMachineKeyIdentityKeysMixin
from .properties import OlmMachineKeyIdentityPropertiesMixin


class OlmMachineKeyIdentityMixin(
    OlmMachineKeyIdentityKeysMixin,
    OlmMachineKeyDeviceSerializationMixin,
    OlmMachineKeyIdentityPropertiesMixin,
):
    """设备身份密钥与 Matrix device-keys 对象构造能力。"""

    pass


OlmMachineKeyIdentityMixin.get_identity_keys = OlmMachineKeyIdentityKeysMixin.__dict__[
    "get_identity_keys"
]
OlmMachineKeyIdentityMixin.get_device_keys = (
    OlmMachineKeyDeviceSerializationMixin.__dict__["get_device_keys"]
)
OlmMachineKeyIdentityMixin.curve25519_key = (
    OlmMachineKeyIdentityPropertiesMixin.__dict__["curve25519_key"]
)
OlmMachineKeyIdentityMixin.ed25519_key = OlmMachineKeyIdentityPropertiesMixin.__dict__[
    "ed25519_key"
]


__all__ = [
    "Any",
    "MEGOLM_ALGO",
    "OLM_ALGO",
    "OlmMachineKeyDeviceSerializationMixin",
    "OlmMachineKeyIdentityKeysMixin",
    "OlmMachineKeyIdentityMixin",
    "OlmMachineKeyIdentityPropertiesMixin",
    "_canonical_json",
]

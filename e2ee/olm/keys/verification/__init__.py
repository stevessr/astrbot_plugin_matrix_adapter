"""Composable Olm device and one-time-key verification mixins."""

from astrbot.api import logger

from ....verification.crypto_utils import _canonical_json
from ...types import Ed25519PublicKey, Ed25519Signature
from .device import OlmMachineKeyDeviceVerificationMixin
from .json import OlmMachineKeyJSONSignatureMixin
from .one_time import OlmMachineKeyOneTimeVerificationMixin


class OlmMachineKeyVerificationMixin(
    OlmMachineKeyJSONSignatureMixin,
    OlmMachineKeyDeviceVerificationMixin,
    OlmMachineKeyOneTimeVerificationMixin,
):
    """Matrix 设备密钥与一次性密钥签名校验能力。"""

    pass


OlmMachineKeyVerificationMixin.verify_json_signature = classmethod(
    OlmMachineKeyJSONSignatureMixin.__dict__["verify_json_signature"].__func__
)
OlmMachineKeyVerificationMixin.verify_device_keys = classmethod(
    OlmMachineKeyDeviceVerificationMixin.__dict__["verify_device_keys"].__func__
)
OlmMachineKeyVerificationMixin.select_verified_one_time_key = classmethod(
    OlmMachineKeyOneTimeVerificationMixin.__dict__[
        "select_verified_one_time_key"
    ].__func__
)


__all__ = [
    "Ed25519PublicKey",
    "Ed25519Signature",
    "OlmMachineKeyDeviceVerificationMixin",
    "OlmMachineKeyJSONSignatureMixin",
    "OlmMachineKeyOneTimeVerificationMixin",
    "OlmMachineKeyVerificationMixin",
    "_canonical_json",
    "logger",
]

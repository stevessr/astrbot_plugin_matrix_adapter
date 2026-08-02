"""Composable Olm message encryption and decryption mixins."""

import base64
import json

from astrbot.api import logger

from .....constants import M_ROOM_KEY, OLM_ALGO
from ...types import (
    AnyOlmMessage,
    Curve25519PublicKey,
    PreKeyMessage,
    Session,
)
from ..sessions import MAX_OLM_SESSIONS_PER_PEER
from .decryption import OlmMachineMessageDecryptionMixin
from .encryption import OlmMachineMessageEncryptionMixin


class OlmMachineMessageMixin(
    OlmMachineMessageEncryptionMixin,
    OlmMachineMessageDecryptionMixin,
):
    """Olm 消息封装、加密与解密能力。"""

    pass


OlmMachineMessageMixin.encrypt_olm = OlmMachineMessageEncryptionMixin.__dict__[
    "encrypt_olm"
]
OlmMachineMessageMixin.decrypt_olm_message = OlmMachineMessageDecryptionMixin.__dict__[
    "decrypt_olm_message"
]


__all__ = [
    "AnyOlmMessage",
    "Curve25519PublicKey",
    "MAX_OLM_SESSIONS_PER_PEER",
    "M_ROOM_KEY",
    "OLM_ALGO",
    "OlmMachineMessageDecryptionMixin",
    "OlmMachineMessageEncryptionMixin",
    "OlmMachineMessageMixin",
    "PreKeyMessage",
    "Session",
    "base64",
    "json",
    "logger",
]

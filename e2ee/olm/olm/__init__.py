"""Composable Olm session and message operations."""

import base64
import json

from astrbot.api import logger

from ....constants import M_ROOM_KEY, OLM_ALGO
from ..types import (
    AnyOlmMessage,
    Curve25519PublicKey,
    PreKeyMessage,
    Session,
)
from .messages import OlmMachineMessageMixin
from .sessions import MAX_OLM_SESSIONS_PER_PEER, OlmMachineSessionMixin


class OlmMachineOlmMixin(OlmMachineSessionMixin, OlmMachineMessageMixin):
    """Olm 会话管理与消息加解密 Mixin。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
OlmMachineOlmMixin.create_outbound_session = (
    OlmMachineSessionMixin.create_outbound_session
)
OlmMachineOlmMixin.get_olm_session = OlmMachineSessionMixin.get_olm_session
OlmMachineOlmMixin.encrypt_olm = OlmMachineMessageMixin.encrypt_olm
OlmMachineOlmMixin.decrypt_olm_message = OlmMachineMessageMixin.decrypt_olm_message


__all__ = [
    "AnyOlmMessage",
    "Curve25519PublicKey",
    "MAX_OLM_SESSIONS_PER_PEER",
    "M_ROOM_KEY",
    "OLM_ALGO",
    "OlmMachineMessageMixin",
    "OlmMachineOlmMixin",
    "OlmMachineSessionMixin",
    "PreKeyMessage",
    "Session",
    "base64",
    "json",
    "logger",
]

"""Composable Megolm outbound lifecycle, recovery, and encryption helpers."""

import json

from astrbot.api import logger

from ....constants import MEGOLM_ALGO
from ...olm.types import GroupSession, InboundGroupSession
from .access import OlmMachineMegolmOutboundAccessMixin
from .creation import OlmMachineMegolmOutboundCreationMixin
from .encryption import OlmMachineMegolmOutboundEncryptionMixin


class OlmMachineMegolmOutboundMixin(
    OlmMachineMegolmOutboundCreationMixin,
    OlmMachineMegolmOutboundAccessMixin,
    OlmMachineMegolmOutboundEncryptionMixin,
):
    """Megolm outbound helpers split by lifecycle and message flow."""

    pass


# Preserve direct method attributes exposed by the former mixin.
OlmMachineMegolmOutboundMixin.create_megolm_outbound_session = (
    OlmMachineMegolmOutboundCreationMixin.create_megolm_outbound_session
)
OlmMachineMegolmOutboundMixin.get_megolm_outbound_shared_history = (
    OlmMachineMegolmOutboundAccessMixin.get_megolm_outbound_shared_history
)
OlmMachineMegolmOutboundMixin.discard_megolm_outbound_session = (
    OlmMachineMegolmOutboundCreationMixin.discard_megolm_outbound_session
)
OlmMachineMegolmOutboundMixin.get_megolm_outbound_session_info = (
    OlmMachineMegolmOutboundAccessMixin.get_megolm_outbound_session_info
)
OlmMachineMegolmOutboundMixin.encrypt_megolm = (
    OlmMachineMegolmOutboundEncryptionMixin.encrypt_megolm
)
OlmMachineMegolmOutboundMixin.get_megolm_outbound_room_ids = (
    OlmMachineMegolmOutboundAccessMixin.get_megolm_outbound_room_ids
)


__all__ = [
    "GroupSession",
    "InboundGroupSession",
    "MEGOLM_ALGO",
    "OlmMachineMegolmOutboundAccessMixin",
    "OlmMachineMegolmOutboundCreationMixin",
    "OlmMachineMegolmOutboundEncryptionMixin",
    "OlmMachineMegolmOutboundMixin",
    "json",
    "logger",
]

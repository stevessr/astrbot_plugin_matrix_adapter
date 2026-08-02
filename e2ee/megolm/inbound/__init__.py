"""Composable Megolm session conversion, import, decryption, and loading helpers."""

import base64
import json

from astrbot.api import logger

from ...constants import MEGOLM_MESSAGE_INDEX_FIELD
from ...olm.types import (
    ExportedSessionKey,
    InboundGroupSession,
    MegolmMessage,
)
from .conversion import _convert_session_key_v2_to_v1
from .decryption import OlmMachineMegolmInboundDecryptionMixin
from .importing import OlmMachineMegolmInboundImportMixin
from .sessions import OlmMachineMegolmInboundSessionsMixin


class OlmMachineMegolmInboundMixin(
    OlmMachineMegolmInboundImportMixin,
    OlmMachineMegolmInboundDecryptionMixin,
    OlmMachineMegolmInboundSessionsMixin,
):
    """Megolm inbound helpers split by conversion, import, and session flow."""

    pass


# Preserve direct method and descriptor attributes exposed by the former mixin.
OlmMachineMegolmInboundMixin.add_megolm_inbound_session = (
    OlmMachineMegolmInboundImportMixin.add_megolm_inbound_session
)
OlmMachineMegolmInboundMixin.get_megolm_first_known_index = staticmethod(
    OlmMachineMegolmInboundDecryptionMixin.get_megolm_first_known_index
)
OlmMachineMegolmInboundMixin.decrypt_megolm = (
    OlmMachineMegolmInboundDecryptionMixin.decrypt_megolm
)
OlmMachineMegolmInboundMixin.get_megolm_inbound_session = (
    OlmMachineMegolmInboundSessionsMixin.get_megolm_inbound_session
)


__all__ = [
    "ExportedSessionKey",
    "InboundGroupSession",
    "MegolmMessage",
    "MEGOLM_MESSAGE_INDEX_FIELD",
    "OlmMachineMegolmInboundDecryptionMixin",
    "OlmMachineMegolmInboundImportMixin",
    "OlmMachineMegolmInboundMixin",
    "OlmMachineMegolmInboundSessionsMixin",
    "_convert_session_key_v2_to_v1",
    "base64",
    "json",
    "logger",
]

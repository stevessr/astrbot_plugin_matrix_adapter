"""Composable encrypted-event and room-key decryption handlers."""

import json

from astrbot.api import logger

from ....constants import MEGOLM_ALGO, OLM_ALGO
from ...constants import (
    VALID_WITHHELD_CODES,
    WITHHELD_NO_OLM,
)
from .decrypt import E2EEManagerDecryptEventMixin
from .room_key import E2EEManagerDecryptRoomKeyMixin


class E2EEManagerDecryptEventsMixin(
    E2EEManagerDecryptEventMixin,
    E2EEManagerDecryptRoomKeyMixin,
):
    """Encrypted event and room-key handlers split by flow."""

    pass


# Preserve direct method attributes exposed by the former mixin.
E2EEManagerDecryptEventsMixin.decrypt_event = E2EEManagerDecryptEventMixin.decrypt_event
E2EEManagerDecryptEventsMixin.handle_room_key = (
    E2EEManagerDecryptRoomKeyMixin.handle_room_key
)


__all__ = [
    "E2EEManagerDecryptEventMixin",
    "E2EEManagerDecryptEventsMixin",
    "E2EEManagerDecryptRoomKeyMixin",
    "MEGOLM_ALGO",
    "OLM_ALGO",
    "VALID_WITHHELD_CODES",
    "WITHHELD_NO_OLM",
    "json",
    "logger",
]

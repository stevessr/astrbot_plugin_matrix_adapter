"""Composable Megolm, Olm, and device validation helpers."""

import hashlib

from astrbot.api import logger

from ...constants import MEGOLM_MESSAGE_INDEX_FIELD
from .devices import E2EEManagerDecryptDeviceValidateMixin
from .megolm import E2EEManagerDecryptMegolmValidateMixin
from .olm import E2EEManagerDecryptOlmValidateMixin


class E2EEManagerDecryptValidateMixin(
    E2EEManagerDecryptMegolmValidateMixin,
    E2EEManagerDecryptOlmValidateMixin,
    E2EEManagerDecryptDeviceValidateMixin,
):
    """Decrypt validation helpers split by plaintext and device concerns."""

    pass


# Preserve direct method attributes exposed by the former mixin.
E2EEManagerDecryptValidateMixin._validate_incoming_megolm_plaintext = (
    E2EEManagerDecryptMegolmValidateMixin._validate_incoming_megolm_plaintext
)
E2EEManagerDecryptValidateMixin._validate_incoming_olm_plaintext = (
    E2EEManagerDecryptOlmValidateMixin._validate_incoming_olm_plaintext
)
E2EEManagerDecryptValidateMixin._find_validated_sender_device = (
    E2EEManagerDecryptDeviceValidateMixin._find_validated_sender_device
)
E2EEManagerDecryptValidateMixin._find_device_by_sender_key = (
    E2EEManagerDecryptDeviceValidateMixin._find_device_by_sender_key
)


__all__ = [
    "E2EEManagerDecryptDeviceValidateMixin",
    "E2EEManagerDecryptMegolmValidateMixin",
    "E2EEManagerDecryptOlmValidateMixin",
    "E2EEManagerDecryptValidateMixin",
    "MEGOLM_MESSAGE_INDEX_FIELD",
    "hashlib",
    "logger",
]

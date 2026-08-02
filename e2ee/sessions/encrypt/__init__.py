"""Composable room-message encryption mixins."""

import time

from astrbot.api import logger

from ...constants import (
    DEFAULT_MEGOLM_ROTATION_PERIOD_MS,
    DEFAULT_MEGOLM_ROTATION_PERIOD_MSGS,
)
from .message import E2EEManagerSessionEncryptMessageMixin
from .rotation import E2EEManagerSessionEncryptRotationMixin
from .sharing import E2EEManagerSessionEncryptSharingMixin


class E2EEManagerSessionEncryptMixin(
    E2EEManagerSessionEncryptRotationMixin,
    E2EEManagerSessionEncryptMessageMixin,
    E2EEManagerSessionEncryptSharingMixin,
):
    """Combined outbound-session encryption mixin."""

    pass


E2EEManagerSessionEncryptMixin._discard_outbound_session = (
    E2EEManagerSessionEncryptRotationMixin.__dict__["_discard_outbound_session"]
)
E2EEManagerSessionEncryptMixin._outbound_session_is_current = (
    E2EEManagerSessionEncryptRotationMixin.__dict__["_outbound_session_is_current"]
)
E2EEManagerSessionEncryptMixin.encrypt_message = (
    E2EEManagerSessionEncryptMessageMixin.__dict__["encrypt_message"]
)
E2EEManagerSessionEncryptMixin._create_and_share_session = (
    E2EEManagerSessionEncryptSharingMixin.__dict__["_create_and_share_session"]
)


__all__ = [
    "DEFAULT_MEGOLM_ROTATION_PERIOD_MS",
    "DEFAULT_MEGOLM_ROTATION_PERIOD_MSGS",
    "E2EEManagerSessionEncryptMessageMixin",
    "E2EEManagerSessionEncryptMixin",
    "E2EEManagerSessionEncryptRotationMixin",
    "E2EEManagerSessionEncryptSharingMixin",
    "logger",
    "time",
]

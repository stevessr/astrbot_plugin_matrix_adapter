"""Key-request response operations."""

import secrets

from astrbot.api import logger

from ....constants import (
    M_FORWARDED_ROOM_KEY,
    M_ROOM_ENCRYPTED,
    MEGOLM_ALGO,
    PREFIX_CURVE25519,
    PREFIX_ED25519,
)
from ...constants import (
    WITHHELD_UNAUTHORISED,
    WITHHELD_UNAVAILABLE,
    WITHHELD_UNVERIFIED,
)
from .operations import E2EEManagerRequestsRespondOperationsMixin


class E2EEManagerRequestsRespondMixin(E2EEManagerRequestsRespondOperationsMixin):
    """Handles forwarding room keys to verified devices."""

    pass


__all__ = [
    "E2EEManagerRequestsRespondMixin",
    "E2EEManagerRequestsRespondOperationsMixin",
    "M_FORWARDED_ROOM_KEY",
    "M_ROOM_ENCRYPTED",
    "MEGOLM_ALGO",
    "PREFIX_CURVE25519",
    "PREFIX_ED25519",
    "WITHHELD_UNAUTHORISED",
    "WITHHELD_UNAVAILABLE",
    "WITHHELD_UNVERIFIED",
    "logger",
    "secrets",
]

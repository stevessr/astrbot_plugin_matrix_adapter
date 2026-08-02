"""Composable SAS ready, start, and accept event handlers."""

from astrbot.api import logger

from .....constants import (
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    M_SAS_V1_METHOD,
)
from .accept import SASVerificationFlowAcceptMixin
from .ready import SASVerificationFlowReadyMixin
from .start import SASVerificationFlowStartEventMixin


class SASVerificationFlowHandshakeMixin(
    SASVerificationFlowReadyMixin,
    SASVerificationFlowStartEventMixin,
    SASVerificationFlowAcceptMixin,
):
    """处理 ready、start 和 accept 事件。"""

    pass


# Preserve direct method attributes exposed by the former monolithic mixin.
SASVerificationFlowHandshakeMixin._handle_ready = (
    SASVerificationFlowReadyMixin._handle_ready
)
SASVerificationFlowHandshakeMixin._handle_start = (
    SASVerificationFlowStartEventMixin._handle_start
)
SASVerificationFlowHandshakeMixin._handle_accept = (
    SASVerificationFlowAcceptMixin._handle_accept
)


__all__ = [
    "M_QR_CODE_SHOW_V1_METHOD",
    "M_RECIPROCATE_V1_METHOD",
    "M_SAS_V1_METHOD",
    "SASVerificationFlowAcceptMixin",
    "SASVerificationFlowHandshakeMixin",
    "SASVerificationFlowReadyMixin",
    "SASVerificationFlowStartEventMixin",
    "logger",
]

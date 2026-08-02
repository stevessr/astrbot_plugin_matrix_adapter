"""Composable SAS verification start-flow handlers."""

from ..constants import VODOZEMAC_SAS_AVAILABLE
from .handshake import SASVerificationFlowHandshakeMixin
from .reciprocate import SASVerificationFlowReciprocateMixin
from .request import SASVerificationFlowRequestMixin


class SASVerificationFlowStartMixin(
    SASVerificationFlowRequestMixin,
    SASVerificationFlowHandshakeMixin,
    SASVerificationFlowReciprocateMixin,
):
    """处理验证请求、SAS 握手和 QR reciprocate 事件。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _method_name in (
    "_handle_request",
    "_handle_ready",
    "_handle_start",
    "_handle_accept",
    "_handle_reciprocate_start",
):
    for _mixin in (
        SASVerificationFlowRequestMixin,
        SASVerificationFlowHandshakeMixin,
        SASVerificationFlowReciprocateMixin,
    ):
        if hasattr(_mixin, _method_name):
            setattr(
                SASVerificationFlowStartMixin,
                _method_name,
                getattr(_mixin, _method_name),
            )
            break

__all__ = [
    "SASVerificationFlowHandshakeMixin",
    "SASVerificationFlowReciprocateMixin",
    "SASVerificationFlowRequestMixin",
    "SASVerificationFlowStartMixin",
    "VODOZEMAC_SAS_AVAILABLE",
]

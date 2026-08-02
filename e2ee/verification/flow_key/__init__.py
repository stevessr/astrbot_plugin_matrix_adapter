"""Composable SAS key-exchange and completion handlers."""

from ..constants import VODOZEMAC_SAS_AVAILABLE
from .completion import SASVerificationFlowCompletionMixin
from .key import SASVerificationFlowKeyExchangeMixin
from .mac import SASVerificationFlowMACMixin


class SASVerificationFlowKeyMixin(
    SASVerificationFlowKeyExchangeMixin,
    SASVerificationFlowMACMixin,
    SASVerificationFlowCompletionMixin,
):
    """处理 SAS key、MAC、done 和 cancel 事件。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _method_name in (
    "_handle_key",
    "_handle_mac",
    "_handle_done",
    "_handle_cancel",
):
    for _mixin in (
        SASVerificationFlowKeyExchangeMixin,
        SASVerificationFlowMACMixin,
        SASVerificationFlowCompletionMixin,
    ):
        if hasattr(_mixin, _method_name):
            setattr(
                SASVerificationFlowKeyMixin,
                _method_name,
                getattr(_mixin, _method_name),
            )
            break

__all__ = [
    "SASVerificationFlowCompletionMixin",
    "SASVerificationFlowKeyExchangeMixin",
    "SASVerificationFlowKeyMixin",
    "SASVerificationFlowMACMixin",
    "VODOZEMAC_SAS_AVAILABLE",
]

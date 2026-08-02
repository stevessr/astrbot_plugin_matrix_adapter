"""Composable verification completion and cancellation operations."""

from astrbot.api import logger

from .cancel import SASVerificationFlowCancelMixin
from .done import SASVerificationFlowDoneMixin


class SASVerificationFlowCompletionMixin(
    SASVerificationFlowDoneMixin,
    SASVerificationFlowCancelMixin,
):
    """处理 done 后的设备持久化、信任发布和取消状态。"""

    pass


# Preserve direct method attributes exposed by the former monolithic mixin.
SASVerificationFlowCompletionMixin._handle_done = (
    SASVerificationFlowDoneMixin._handle_done
)
SASVerificationFlowCompletionMixin._handle_cancel = (
    SASVerificationFlowCancelMixin._handle_cancel
)


__all__ = [
    "SASVerificationFlowCancelMixin",
    "SASVerificationFlowCompletionMixin",
    "SASVerificationFlowDoneMixin",
    "logger",
]

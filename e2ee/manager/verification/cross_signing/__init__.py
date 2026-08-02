"""Composable cross-signing state and trusted-device publication."""

import time

from astrbot.api import logger

from .....constants import PREFIX_ED25519
from .publication import CrossSigningVerificationPublicationMixin
from .state import CrossSigningVerificationStateMixin


class E2EEManagerVerificationCrossSigningMixin(
    CrossSigningVerificationStateMixin,
    CrossSigningVerificationPublicationMixin,
):
    """检查同账号设备签名状态并发布设备信任。"""

    pass


# Preserve direct method attributes exposed by the former monolithic mixin.
E2EEManagerVerificationCrossSigningMixin._extract_cross_signing_key_id = staticmethod(
    CrossSigningVerificationStateMixin._extract_cross_signing_key_id
)
E2EEManagerVerificationCrossSigningMixin._classify_own_device_cross_signing_state = (
    CrossSigningVerificationStateMixin._classify_own_device_cross_signing_state
)
E2EEManagerVerificationCrossSigningMixin._format_masked_device_ids = (
    CrossSigningVerificationStateMixin._format_masked_device_ids
)
E2EEManagerVerificationCrossSigningMixin._log_manual_same_user_verification_required = (
    CrossSigningVerificationStateMixin._log_manual_same_user_verification_required
)
E2EEManagerVerificationCrossSigningMixin._log_same_user_verification_gap = (
    CrossSigningVerificationStateMixin._log_same_user_verification_gap
)
E2EEManagerVerificationCrossSigningMixin._maybe_republish_current_device_keys_after_verification = CrossSigningVerificationPublicationMixin._maybe_republish_current_device_keys_after_verification
E2EEManagerVerificationCrossSigningMixin.publish_trusted_device = (
    CrossSigningVerificationPublicationMixin.publish_trusted_device
)


__all__ = [
    "CrossSigningVerificationPublicationMixin",
    "CrossSigningVerificationStateMixin",
    "E2EEManagerVerificationCrossSigningMixin",
    "PREFIX_ED25519",
    "logger",
    "time",
]

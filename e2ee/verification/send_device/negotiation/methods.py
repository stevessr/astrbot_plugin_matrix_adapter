"""Verification method negotiation and identity-key selection."""

from .....constants import (
    M_QR_CODE_SCAN_V1_METHOD,
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
)
from ...constants import SAS_METHODS


class SASVerificationSendDeviceNegotiationMethodsMixin:
    """协商验证算法并选择需要加入 MAC 的本地身份密钥。"""

    def _get_supported_verification_methods(
        self, other_user: str | None = None
    ) -> list[str]:
        methods = list(SAS_METHODS)
        if other_user == self.user_id:
            for method in (
                M_QR_CODE_SCAN_V1_METHOD,
                M_QR_CODE_SHOW_V1_METHOD,
                M_RECIPROCATE_V1_METHOD,
            ):
                if method not in methods:
                    methods.append(method)
        return methods

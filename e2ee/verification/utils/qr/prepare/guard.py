"""Self-verification QR readiness checks."""

from ......constants import M_QR_CODE_SCAN_V1_METHOD


class SASVerificationFlowQRPrepareGuardMixin:
    """Check whether a self-verification QR should be prepared."""

    def _check_self_verification_qr_ready(
        self,
        sender: str,
        peer_device: str | None,
        methods: object,
    ) -> bool:
        if sender != self.user_id or not peer_device:
            return False
        if not self._supports_method(methods, M_QR_CODE_SCAN_V1_METHOD):
            return False
        return True


__all__ = ["SASVerificationFlowQRPrepareGuardMixin"]

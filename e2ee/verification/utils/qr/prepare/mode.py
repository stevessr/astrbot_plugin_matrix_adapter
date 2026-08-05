"""Mode selection for self-verification QR codes."""

from ......constants import (
    QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER,
    QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER,
)


class SASVerificationFlowQRPrepareModeMixin:
    """Select the QR mode and ordered key pair."""

    def _select_self_verification_qr_mode(
        self,
        response: dict,
        sender: str,
        peer_device_key: str,
        current_device_key: str,
        master_key: str,
    ) -> tuple:
        """Return ``(mode, key1, key2)`` for the QR payload."""
        if self._device_trusts_master_key(response, sender, self.device_id):
            mode = QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER
            key1, key2 = master_key, peer_device_key
        else:
            mode = QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER
            key1, key2 = current_device_key, master_key
        return mode, key1, key2


__all__ = ["SASVerificationFlowQRPrepareModeMixin"]

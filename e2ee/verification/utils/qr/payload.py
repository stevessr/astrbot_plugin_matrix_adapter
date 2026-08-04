"""Self-verification QR payload encoding."""

from .....constants import QR_CODE_HEADER, QR_CODE_VERSION


class SASVerificationFlowQRPayloadMixin:
    def _build_self_verification_qr_payload(
        self,
        transaction_id: str,
        key1: str,
        key2: str,
        shared_secret: bytes,
        mode: int,
    ) -> bytes:
        return b"".join(
            [
                QR_CODE_HEADER,
                bytes([QR_CODE_VERSION, mode]),
                len(transaction_id).to_bytes(2, "big"),
                transaction_id.encode("ascii"),
                self._decode_unpadded_base64(key1),
                self._decode_unpadded_base64(key2),
                shared_secret,
            ]
        )

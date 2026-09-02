"""Matrix verification QR payload encoding."""

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
        """Build the MSC1544 binary QR payload.

        The verification request ID is an opaque Matrix string and the stable
        format prefixes its UTF-8 *byte* length, not its Python character count.
        """
        transaction_bytes = transaction_id.encode("utf-8")
        if len(transaction_bytes) > 0xFFFF:
            raise ValueError("QR verification transaction ID is too long")
        return b"".join(
            [
                QR_CODE_HEADER,
                bytes([QR_CODE_VERSION, mode]),
                len(transaction_bytes).to_bytes(2, "big"),
                transaction_bytes,
                self._decode_unpadded_base64(key1),
                self._decode_unpadded_base64(key2),
                shared_secret,
            ]
        )

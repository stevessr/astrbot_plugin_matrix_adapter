import base64


class SASVerificationFlowMaskingMixin:
    @staticmethod
    def _mask_identifier(value: str | None) -> str:
        if not isinstance(value, str) or not value:
            return "<empty>"
        normalized = value.strip()
        if len(normalized) <= 4:
            return "***"
        return f"{normalized[:2]}***{normalized[-2:]}"

    @staticmethod
    def _mask_txn_id(value: str | None) -> str:
        if not isinstance(value, str) or not value:
            return "<empty>"
        normalized = value.strip()
        if len(normalized) <= 8:
            return "***"
        return f"{normalized[:8]}..."

    @staticmethod
    def _supports_method(methods: object, method: str) -> bool:
        if not isinstance(methods, (list, tuple, set)):
            return False
        return method in methods

    @staticmethod
    def _decode_unpadded_base64(data: str) -> bytes:
        normalized = str(data or "").strip()
        if not normalized:
            return b""
        padding = "=" * (-len(normalized) % 4)
        return base64.b64decode(normalized + padding)

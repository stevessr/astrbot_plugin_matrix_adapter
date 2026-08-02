from __future__ import annotations


class SASVerificationManualNotifyMaskingMixin:
    @staticmethod
    def _mask_txn_id(value: str | None) -> str:
        if not isinstance(value, str) or not value:
            return "<empty>"
        normalized = value.strip()
        if len(normalized) <= 8:
            return "***"
        return f"{normalized[:8]}..."

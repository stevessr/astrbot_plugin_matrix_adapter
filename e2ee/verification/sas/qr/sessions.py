"""QR scan session matching helpers."""

from typing import Any


class SASVerificationQRSessionMixin:
    """为二维码扫描选择待处理的验证会话。"""

    def _find_session_for_qr_scan(
        self,
        user_id: str,
        device_id: str,
        transaction_id: str | None = None,
    ) -> tuple[str, dict[str, Any]] | tuple[None, None]:
        candidates: list[tuple[str, dict[str, Any]]] = []
        for txn_id, session in self._sessions.items():
            if transaction_id and txn_id != transaction_id:
                continue
            if session.get("sender") != user_id:
                continue
            if (
                session.get("from_device") != device_id
                and session.get("their_device") != device_id
            ):
                continue
            if session.get("state") in ("done", "cancelled"):
                continue
            candidates.append((txn_id, session))

        if not candidates:
            return None, None

        for txn_id, session in candidates:
            if session.get("state") in ("ready", "ready_for_qr_scan", "requested"):
                return txn_id, session
        return candidates[0]

"""Incoming SAS verification request handling."""

import sys
import time

from astrbot.api import logger

from ...constants import VODOZEMAC_SAS_AVAILABLE, Sas


class SASVerificationFlowRequestCoreMixin:
    """处理验证请求、设备指纹查询和验证模式分派。"""

    _REQUEST_MAX_FUTURE_MS = 5 * 60 * 1000
    _REQUEST_MAX_AGE_MS = 10 * 60 * 1000

    @classmethod
    def _is_fresh_to_device_verification_request(cls, timestamp: object) -> bool:
        """Validate the stable Matrix to-device verification request window."""
        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            return False
        now_ms = int(time.time() * 1000)
        return (
            now_ms - cls._REQUEST_MAX_AGE_MS
            <= timestamp
            <= now_ms + cls._REQUEST_MAX_FUTURE_MS
        )

    async def _handle_request(self, sender: str, content: dict, transaction_id: str):
        """处理验证请求"""
        from_device = content.get("from_device")
        methods = content.get("methods", [])
        if not from_device:
            logger.warning("[E2EE-Verify] 验证请求缺少 from_device，忽略")
            return

        timestamp = content.get("timestamp")
        if not self._is_fresh_to_device_verification_request(timestamp):
            logger.warning(
                "[E2EE-Verify] 忽略过期、过早或缺少 timestamp 的 to-device 验证请求："
                f"sender={self._mask_identifier(sender)} "
                f"device={self._mask_identifier(from_device)}"
            )
            return

        if transaction_id in self._sessions:
            existing = self._sessions.get(transaction_id) or {}
            logger.warning(
                "[E2EE-Verify] 忽略重复 verification transaction，保留原会话："
                f"txn={self._mask_txn_id(transaction_id)} "
                f"sender={self._mask_identifier(sender)} "
                f"device={self._mask_identifier(from_device)} "
                f"existing_state={existing.get('state')}"
            )
            return

        # Stable verification forbids a device from driving multiple concurrent
        # verification attempts. Cancel both the existing flow(s) and this new
        # request instead of allowing the newest transaction to replace the old.
        if await self._cancel_parallel_verification_attempts(
            sender,
            from_device,
            transaction_id,
        ):
            return

        logger.info(
            f"[E2EE-Verify] 收到验证请求："
            f"sender={self._mask_identifier(sender)} "
            f"device={self._mask_identifier(from_device)} methods={methods}"
        )

        # 创建 SAS 实例
        sas = None
        if _vodozemac_sas_available():
            try:
                sas = Sas()
                logger.debug("[E2EE-Verify] 创建 SAS 实例")
            except Exception as e:
                logger.warning(f"[E2EE-Verify] 创建 SAS 实例失败：{e}")

        self._sessions[transaction_id] = {
            "sender": sender,
            "from_device": from_device,
            "methods": methods,
            "state": "requested",
            "sas": sas,
        }

        session = self._sessions[transaction_id]
        self._initialize_verification_session_lifecycle(session, transaction_id)
        await self._query_request_verification_keys(session, sender, from_device)

        await self._dispatch_verification_mode(
            session,
            sender,
            from_device,
            methods,
            transaction_id,
        )


def _vodozemac_sas_available() -> bool:
    package = sys.modules.get(__package__.rsplit(".", 1)[0])
    if package is not None:
        return bool(
            getattr(package, "VODOZEMAC_SAS_AVAILABLE", VODOZEMAC_SAS_AVAILABLE)
        )
    return VODOZEMAC_SAS_AVAILABLE

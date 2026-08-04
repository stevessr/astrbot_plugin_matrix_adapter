"""Incoming SAS verification request handling."""

import sys

from astrbot.api import logger

from ...constants import VODOZEMAC_SAS_AVAILABLE, Sas


class SASVerificationFlowRequestCoreMixin:
    """处理验证请求、设备指纹查询和验证模式分派。"""

    async def _handle_request(self, sender: str, content: dict, transaction_id: str):
        """处理验证请求"""
        from_device = content.get("from_device")
        methods = content.get("methods", [])
        if not from_device:
            logger.warning("[E2EE-Verify] 验证请求缺少 from_device，忽略")
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

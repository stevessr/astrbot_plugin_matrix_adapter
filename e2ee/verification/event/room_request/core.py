"""In-room verification request and trust-on-first-use handling."""

import sys

from astrbot.api import logger

from ...constants import VODOZEMAC_SAS_AVAILABLE, Sas


def _vodozemac_sas_available() -> bool:
    package = sys.modules.get(__package__.rsplit(".", 1)[0])
    if package is not None:
        return bool(
            getattr(package, "VODOZEMAC_SAS_AVAILABLE", VODOZEMAC_SAS_AVAILABLE)
        )
    return VODOZEMAC_SAS_AVAILABLE


class SASVerificationRoomRequestCoreMixin:
    """处理房间内验证请求、设备信任查询和自动确认策略。"""

    async def _handle_in_room_request(
        self, sender: str, content: dict, transaction_id: str
    ):
        """处理房间内验证请求"""
        from_device = content.get("from_device")
        methods = content.get("methods") or []

        if not from_device:
            logger.warning("[E2EE-Verify] 房间内验证请求缺少 from_device")
            return

        session = self._sessions.get(transaction_id)
        if session is None:
            # Direct unit callers may bypass the room dispatcher.
            session = {}
            self._sessions[transaction_id] = session
        elif not session.get("_room_context_only"):
            logger.warning(
                "[E2EE-Verify] 忽略重复房间 verification transaction，保留原会话："
                f"txn={self._mask_txn_id(transaction_id)} "
                f"sender={self._mask_identifier(sender)} "
                f"device={self._mask_identifier(from_device)} "
                f"existing_state={session.get('state')}"
            )
            return

        session.pop("_room_context_only", None)

        logger.info(
            f"[E2EE-Verify] 收到房间内验证请求："
            f"sender={sender} device={from_device} methods={methods}"
        )

        # 创建 SAS 实例
        sas = None
        if _vodozemac_sas_available():
            try:
                sas = Sas()
                pub = sas.public_key.to_base64()
                logger.debug(
                    f"[E2EE-Verify] 创建 SAS 实例，公钥：{(pub or '')[:16]}..."
                )
            except Exception as e:
                logger.warning(f"[E2EE-Verify] 创建 SAS 实例失败：{e}")

        session.update(
            {
                "sender": sender,
                "from_device": from_device,
                "methods": methods,
                "state": "requested",
                "sas": sas,
            }
        )

        # TOFU: Check if device is trusted
        fingerprint = await self._query_device_fingerprint(sender, from_device)
        if not await self._evaluate_device_trust(
            session, sender, from_device, fingerprint
        ):
            return

        await self._apply_room_request_policy(session, methods, transaction_id)

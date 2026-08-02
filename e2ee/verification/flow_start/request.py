"""Incoming SAS verification request handling."""

import sys

from astrbot.api import logger

from ....constants import (
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    M_SAS_V1_METHOD,
    PREFIX_ED25519,
)
from ..constants import VODOZEMAC_SAS_AVAILABLE, Sas


def _vodozemac_sas_available() -> bool:
    package = sys.modules.get(__package__)
    if package is not None:
        return bool(
            getattr(package, "VODOZEMAC_SAS_AVAILABLE", VODOZEMAC_SAS_AVAILABLE)
        )
    return VODOZEMAC_SAS_AVAILABLE


class SASVerificationFlowRequestMixin:
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
        try:
            resp = await self.client.query_keys({sender: []})
            devices = resp.get("device_keys") or {}
            user_devices = devices.get(sender) or {}
            device_info = user_devices.get(from_device) or {}
            keys = device_info.get("keys") or {}
            fingerprint = keys.get(f"{PREFIX_ED25519}{from_device}")
            if fingerprint:
                session["fingerprint"] = fingerprint
                logger.debug(
                    "[E2EE-Verify] 已获取设备指纹："
                    f"device={self._mask_identifier(from_device)}"
                )
            else:
                logger.warning(
                    "[E2EE-Verify] 未找到设备指纹："
                    f"sender={self._mask_identifier(sender)} "
                    f"device={self._mask_identifier(from_device)}"
                )

            master_key_obj = (resp.get("master_keys") or {}).get(sender) or {}
            master_keys = master_key_obj.get("keys") or {}
            if master_keys:
                master_key_id, master_key = next(iter(master_keys.items()))
                session["master_key_id"] = master_key_id
                session["master_key"] = master_key
        except Exception as e:
            logger.warning(
                "[E2EE-Verify] 查询验证设备指纹失败："
                f"sender={self._mask_identifier(sender)} "
                f"device={self._mask_identifier(from_device)} err={e}"
            )

        if self.auto_verify_mode == "auto_reject":
            logger.info("[E2EE-Verify] 自动拒绝验证请求 (mode=auto_reject)")
            await self._send_cancel(
                sender, from_device, transaction_id, "m.user", "自动拒绝"
            )
            return

        if self.auto_verify_mode == "manual":
            logger.info(
                "[E2EE-Verify] 手动模式，发送 ready 并等待管理员确认 (mode=manual)"
            )
            if self._supports_method(
                methods, M_SAS_V1_METHOD
            ) or self._can_continue_with_qr(sender, methods):
                await self._send_ready(sender, from_device, transaction_id)
                await self._maybe_prepare_self_verification_qr(
                    sender, from_device, methods, transaction_id
                )
                if (
                    sender == self.user_id
                    and self._supports_method(methods, M_QR_CODE_SHOW_V1_METHOD)
                    and self._supports_method(methods, M_RECIPROCATE_V1_METHOD)
                ):
                    notify_scan = getattr(self, "_notify_admin_to_scan_peer_qr", None)
                    if callable(notify_scan):
                        await notify_scan(
                            self._sessions[transaction_id], transaction_id
                        )
            else:
                await self._send_cancel(
                    sender,
                    from_device,
                    transaction_id,
                    "m.unknown_method",
                    "不支持的验证方法",
                )
            return

        # auto_accept: 发送 ready
        if self._supports_method(
            methods, M_SAS_V1_METHOD
        ) or self._can_continue_with_qr(sender, methods):
            logger.info("[E2EE-Verify] 自动接受验证请求 (mode=auto_accept)")
            await self._send_ready(sender, from_device, transaction_id)
            await self._maybe_prepare_self_verification_qr(
                sender, from_device, methods, transaction_id
            )
            if (
                sender == self.user_id
                and self._supports_method(methods, M_QR_CODE_SHOW_V1_METHOD)
                and self._supports_method(methods, M_RECIPROCATE_V1_METHOD)
            ):
                notify_scan = getattr(self, "_notify_admin_to_scan_peer_qr", None)
                if callable(notify_scan):
                    await notify_scan(self._sessions[transaction_id], transaction_id)
        else:
            logger.warning(f"[E2EE-Verify] 不支持的验证方法：{methods}")
            await self._send_cancel(
                sender,
                from_device,
                transaction_id,
                "m.unknown_method",
                "不支持的验证方法",
            )


__all__ = ["SASVerificationFlowRequestMixin"]

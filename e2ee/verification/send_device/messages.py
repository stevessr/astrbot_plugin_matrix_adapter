"""Verification MAC, completion, cancellation, and transport messages."""

import base64
import hashlib
import secrets
import sys

from astrbot.api import logger

from ....constants import (
    INFO_PREFIX_MAC,
    M_KEY_VERIFICATION_CANCEL,
    M_KEY_VERIFICATION_DONE,
    M_KEY_VERIFICATION_MAC,
)
from ..constants import VODOZEMAC_SAS_AVAILABLE
from ..crypto_utils import _compute_hkdf


def _vodozemac_sas_available() -> bool:
    package = sys.modules.get(__package__)
    if package is not None:
        return bool(
            getattr(package, "VODOZEMAC_SAS_AVAILABLE", VODOZEMAC_SAS_AVAILABLE)
        )
    return VODOZEMAC_SAS_AVAILABLE


class SASVerificationSendDeviceMessagesMixin:
    """发送验证 MAC、done、cancel 以及底层 to-device 消息。"""

    async def _send_mac(
        self, to_user: str, to_device: str, transaction_id: str, session: dict
    ):
        """发送 MAC - 使用 HKDF-HMAC-SHA256.v2"""
        established_sas = session.get("established_sas")
        sas_bytes = session.get("sas_bytes", b"\x00" * 32)

        # 生成 MAC 的基础密钥
        keys_to_mac = await self._get_verification_keys_to_mac(
            other_user=to_user,
            session=session,
        )

        if not keys_to_mac:
            logger.warning("[E2EE-Verify] 缺少可用于发送 MAC 的本地身份密钥")
            return

        if established_sas and _vodozemac_sas_available():
            try:
                # 根据 Matrix 规范，info 格式为：
                # MATRIX_KEY_VERIFICATION_MAC + user_id + device_id + other_user_id + other_device_id + transaction_id + key_id
                base_info = f"{INFO_PREFIX_MAC}{self.user_id}{self.device_id}{to_user}{to_device}{transaction_id}"

                key_ids = sorted(keys_to_mac.keys())
                mac_content = {
                    key_id: established_sas.calculate_mac(
                        keys_to_mac[key_id], (base_info + key_id)
                    )
                    for key_id in key_ids
                }
                keys_mac = established_sas.calculate_mac(
                    ",".join(key_ids), (base_info + "KEY_IDS")
                )
            except Exception as e:
                logger.warning(f"[E2EE-Verify] vodozemac MAC 计算失败，使用回退：{e}")
                # 回退实现
                key_ids = sorted(keys_to_mac.keys())
                mac_content = {
                    key_id: base64.b64encode(
                        _compute_hkdf(sas_bytes, b"", keys_to_mac[key_id].encode())
                    ).decode()
                    for key_id in key_ids
                }
                keys_mac = base64.b64encode(
                    hashlib.sha256(",".join(key_ids).encode()).digest()
                ).decode()
        else:
            # 回退实现
            key_ids = sorted(keys_to_mac.keys())
            mac_content = {
                key_id: base64.b64encode(
                    _compute_hkdf(sas_bytes, b"", keys_to_mac[key_id].encode())
                ).decode()
                for key_id in key_ids
            }
            keys_mac = base64.b64encode(
                hashlib.sha256(",".join(key_ids).encode()).digest()
            ).decode()

        content = {
            "transaction_id": transaction_id,
            "mac": mac_content,
            "keys": keys_mac,
        }

        await self._send_to_device(M_KEY_VERIFICATION_MAC, to_user, to_device, content)
        logger.info("[E2EE-Verify] 已发送 mac")

    async def _send_done(self, to_user: str, to_device: str, transaction_id: str):
        """发送 done"""
        content = {"transaction_id": transaction_id}
        await self._send_to_device(M_KEY_VERIFICATION_DONE, to_user, to_device, content)
        logger.info("[E2EE-Verify] 已发送 done")

    async def _send_cancel(
        self, to_user: str, to_device: str, transaction_id: str, code: str, reason: str
    ):
        """发送取消"""
        content = {
            "transaction_id": transaction_id,
            "code": code,
            "reason": reason,
        }
        await self._send_to_device(
            M_KEY_VERIFICATION_CANCEL, to_user, to_device, content
        )
        logger.info(f"[E2EE-Verify] 已发送 cancel: {code} - {reason}")

    async def _send_to_device(
        self, event_type: str, to_user: str, to_device: str, content: dict
    ):
        """发送 to_device 消息"""
        try:
            txn_id = secrets.token_hex(16)
            messages = {to_user: {to_device: content}}
            await self.client.send_to_device(event_type, messages, txn_id)
        except Exception as e:
            logger.error(f"[E2EE-Verify] 发送 {event_type} 失败：{e}")


__all__ = ["SASVerificationSendDeviceMessagesMixin"]

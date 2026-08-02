"""Verification MAC message generation."""

import base64
import hashlib

from astrbot.api import logger

from .....constants import INFO_PREFIX_MAC, M_KEY_VERIFICATION_MAC
from ...crypto_utils import _compute_hkdf
from .compat import _vodozemac_sas_available


class SASVerificationSendDeviceMACMixin:
    async def _send_mac(
        self, to_user: str, to_device: str, transaction_id: str, session: dict
    ):
        """发送 MAC - 使用 HKDF-HMAC-SHA256.v2"""
        established_sas = session.get("established_sas")
        sas_bytes = session.get("sas_bytes", b"\x00" * 32)
        keys_to_mac = await self._get_verification_keys_to_mac(
            other_user=to_user, session=session
        )
        if not keys_to_mac:
            logger.warning("[E2EE-Verify] 缺少可用于发送 MAC 的本地身份密钥")
            return
        if established_sas and _vodozemac_sas_available():
            try:
                base_info = f"{INFO_PREFIX_MAC}{self.user_id}{self.device_id}{to_user}{to_device}{transaction_id}"
                key_ids = sorted(keys_to_mac.keys())
                mac_content = {
                    key_id: established_sas.calculate_mac(
                        keys_to_mac[key_id], base_info + key_id
                    )
                    for key_id in key_ids
                }
                keys_mac = established_sas.calculate_mac(
                    ",".join(key_ids), base_info + "KEY_IDS"
                )
            except Exception as e:
                logger.warning(f"[E2EE-Verify] vodozemac MAC 计算失败，使用回退：{e}")
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

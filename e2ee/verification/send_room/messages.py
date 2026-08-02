"""In-room SAS MAC, completion, and cancellation messages."""

import base64
import hashlib
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


class SASVerificationSendRoomMessagesMixin:
    """发送房间内 MAC、done 和 cancel 消息。"""

    async def _send_in_room_mac(self, room_id: str, transaction_id: str, session: dict):
        """发送房间内 MAC - 使用 HKDF-HMAC-SHA256.v2"""
        established_sas = session.get("established_sas")
        sas_bytes = session.get("sas_bytes", b"\x00" * 32)

        # Get their user and device info from session
        to_user = session.get("sender")
        to_device = session.get("from_device", session.get("their_device", ""))
        keys_to_mac = await self._get_verification_keys_to_mac(
            other_user=to_user,
            session=session,
        )

        if not keys_to_mac:
            logger.warning("[E2EE-Verify] 缺少可用于发送房间内 MAC 的本地身份密钥")
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
            "mac": mac_content,
            "keys": keys_mac,
        }

        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_MAC, content, transaction_id
        )
        logger.info("[E2EE-Verify] 已发送 mac")

    async def _send_in_room_done(self, room_id: str, transaction_id: str):
        """发送房间内 done"""
        content = {}
        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_DONE, content, transaction_id
        )
        logger.info("[E2EE-Verify] 已发送 done")

    async def _send_in_room_cancel(
        self, room_id: str, transaction_id: str, code: str, reason: str
    ):
        """发送房间内取消"""
        content = {
            "code": code,
            "reason": reason,
        }
        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_CANCEL, content, transaction_id
        )
        logger.info(f"[E2EE-Verify] 已发送房间内 cancel: {code} - {reason}")


__all__ = ["SASVerificationSendRoomMessagesMixin"]

"""SAS MAC verification and failure handling."""

import base64
import hashlib
import hmac

from astrbot.api import logger

from ....constants import INFO_PREFIX_MAC, PREFIX_ED25519
from ..crypto_utils import _compute_hkdf


class SASVerificationFlowMACMixin:
    """校验对端 MAC 并在失败时发送取消。"""

    async def _handle_mac(self, sender: str, content: dict, transaction_id: str):
        """处理 MAC 验证"""
        their_mac = content.get("mac") or {}
        their_keys = content.get("keys")

        logger.debug(f"[E2EE-Verify] 收到 MAC: keys={their_keys}")

        session = self._sessions.get(transaction_id, {})
        session["their_mac"] = their_mac
        session["state"] = "mac_received"

        established_sas = session.get("established_sas")
        their_device = session.get("from_device", session.get("their_device", ""))
        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")
        sas_bytes = session.get("sas_bytes", b"\x00" * 32)

        async def _cancel_mac_verification(reason: str):
            logger.warning(f"[E2EE-Verify] MAC 校验失败：{reason}")
            session["state"] = "cancelled"
            session["cancel_code"] = "m.key_mismatch"
            session["cancel_reason"] = reason
            if is_in_room and room_id:
                await self._send_in_room_cancel(
                    room_id,
                    transaction_id,
                    "m.key_mismatch",
                    reason,
                )
            else:
                await self._send_cancel(
                    sender,
                    their_device,
                    transaction_id,
                    "m.key_mismatch",
                    reason,
                )

        if not isinstance(their_mac, dict) or not their_mac:
            await _cancel_mac_verification("MAC verification failed")
            return

        available_keys: dict[str, str] = {}
        fingerprint = session.get("fingerprint")
        if fingerprint and their_device:
            available_keys[f"{PREFIX_ED25519}{their_device}"] = fingerprint

        master_key = session.get("master_key")
        master_key_id = session.get("master_key_id")
        if master_key_id and master_key:
            available_keys[master_key_id] = master_key

        if their_device and (
            f"{PREFIX_ED25519}{their_device}" not in available_keys or not master_key_id
        ):
            try:
                resp = await self.client.query_keys({sender: []})
                devices = resp.get("device_keys") or {}
                user_devices = devices.get(sender) or {}
                device_info = user_devices.get(their_device) or {}
                keys = device_info.get("keys") or {}
                fingerprint = keys.get(f"{PREFIX_ED25519}{their_device}")
                if fingerprint:
                    session["fingerprint"] = fingerprint
                    available_keys[f"{PREFIX_ED25519}{their_device}"] = fingerprint

                master_key_obj = (resp.get("master_keys") or {}).get(sender) or {}
                master_keys = master_key_obj.get("keys") or {}
                if master_keys:
                    fetched_master_key_id, fetched_master_key = next(
                        iter(master_keys.items())
                    )
                    session["master_key_id"] = fetched_master_key_id
                    session["master_key"] = fetched_master_key
                    available_keys[fetched_master_key_id] = fetched_master_key
            except Exception as e:
                logger.warning(f"[E2EE-Verify] 查询 MAC 校验密钥失败：{e}")

        if not their_device or not available_keys:
            await _cancel_mac_verification("MAC verification failed")
            return

        key_ids = sorted(their_mac.keys())
        if not key_ids:
            await _cancel_mac_verification("MAC verification failed")
            return

        for key_id in key_ids:
            if key_id not in available_keys:
                await _cancel_mac_verification("MAC verification failed")
                return
            if not isinstance(their_mac.get(key_id), str):
                await _cancel_mac_verification("MAC verification failed")
                return

        base_info = f"{INFO_PREFIX_MAC}{sender}{their_device}{self.user_id}{self.device_id}{transaction_id}"
        key_ids_csv = ",".join(key_ids)

        try:
            if established_sas:
                expected_mac_map = {
                    key_id: established_sas.calculate_mac(
                        available_keys[key_id], (base_info + key_id)
                    )
                    for key_id in key_ids
                }
                expected_keys_mac = established_sas.calculate_mac(
                    key_ids_csv, (base_info + "KEY_IDS")
                )
            else:
                expected_mac_map = {
                    key_id: base64.b64encode(
                        _compute_hkdf(sas_bytes, b"", available_keys[key_id].encode())
                    ).decode()
                    for key_id in key_ids
                }
                expected_keys_mac = base64.b64encode(
                    hashlib.sha256(key_ids_csv.encode()).digest()
                ).decode()
        except Exception as e:
            logger.error(f"[E2EE-Verify] MAC 计算失败：{e}")
            await _cancel_mac_verification("MAC verification failed")
            return

        if not isinstance(their_keys, str):
            await _cancel_mac_verification("MAC verification failed")
            return

        for key_id in key_ids:
            actual_mac = their_mac.get(key_id)
            if not hmac.compare_digest(actual_mac, expected_mac_map[key_id]):
                await _cancel_mac_verification("MAC verification failed")
                return

        if not hmac.compare_digest(their_keys, expected_keys_mac):
            await _cancel_mac_verification("MAC verification failed")
            return

        session["mac_verified"] = True
        logger.info(
            "[E2EE-Verify] ✅ MAC 校验通过："
            f"device={self._mask_identifier(their_device)}"
        )

        if self.auto_verify_mode == "auto_accept" and not session.get("done_sent"):
            session["done_sent"] = True
            if is_in_room and room_id:
                await self._send_in_room_done(room_id, transaction_id)
            else:
                await self._send_done(
                    sender,
                    session.get("their_device", session.get("from_device", "")),
                    transaction_id,
                )


__all__ = ["SASVerificationFlowMACMixin"]

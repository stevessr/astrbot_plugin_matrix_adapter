"""SAS MAC verification and failure handling."""

import hmac

from astrbot.api import logger

from .....constants import INFO_PREFIX_MAC


class SASVerificationFlowMACCoreMixin:
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

        if not isinstance(their_mac, dict) or not their_mac:
            await self._cancel_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
                "MAC verification failed",
            )
            return

        available_keys = await self._collect_mac_verification_keys(
            session,
            sender,
            their_device,
        )

        if not their_device or not available_keys:
            await self._cancel_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
                "MAC verification failed",
            )
            return

        key_ids = sorted(their_mac.keys())
        if not key_ids:
            await self._cancel_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
                "MAC verification failed",
            )
            return

        for key_id in key_ids:
            if key_id not in available_keys:
                await self._cancel_mac_verification(
                    session,
                    sender,
                    their_device,
                    is_in_room,
                    room_id,
                    transaction_id,
                    "MAC verification failed",
                )
                return
            if not isinstance(their_mac.get(key_id), str):
                await self._cancel_mac_verification(
                    session,
                    sender,
                    their_device,
                    is_in_room,
                    room_id,
                    transaction_id,
                    "MAC verification failed",
                )
                return

        base_info = f"{INFO_PREFIX_MAC}{sender}{their_device}{self.user_id}{self.device_id}{transaction_id}"
        key_ids_csv = ",".join(key_ids)

        expected = await self._compute_expected_macs(
            session,
            sas_bytes,
            established_sas,
            key_ids,
            key_ids_csv,
            base_info,
            available_keys,
        )
        if expected is None:
            await self._cancel_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
                "MAC verification failed",
            )
            return
        expected_mac_map, expected_keys_mac = expected

        if not isinstance(their_keys, str):
            await self._cancel_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
                "MAC verification failed",
            )
            return

        for key_id in key_ids:
            actual_mac = their_mac.get(key_id)
            if not hmac.compare_digest(actual_mac, expected_mac_map[key_id]):
                await self._cancel_mac_verification(
                    session,
                    sender,
                    their_device,
                    is_in_room,
                    room_id,
                    transaction_id,
                    "MAC verification failed",
                )
                return

        if not hmac.compare_digest(their_keys, expected_keys_mac):
            await self._cancel_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
                "MAC verification failed",
            )
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

    async def _cancel_mac_verification(
        self,
        session: dict,
        sender: str,
        their_device: str,
        is_in_room: bool,
        room_id,
        transaction_id: str,
        reason: str,
    ):
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

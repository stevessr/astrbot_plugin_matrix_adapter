"""SAS MAC verification orchestration."""

from astrbot.api import logger

from .......constants import INFO_PREFIX_MAC
from .finish import SASVerificationFlowMACFinishMixin
from .keycheck import SASVerificationFlowMACKeyCheckMixin
from .record import SASVerificationFlowMACRecordMixin


class SASVerificationFlowMACOrchestratorMixin(
    SASVerificationFlowMACRecordMixin,
    SASVerificationFlowMACKeyCheckMixin,
    SASVerificationFlowMACFinishMixin,
):
    """校验对端 MAC 并在失败时发送取消。"""

    async def _handle_mac(self, sender: str, content: dict, transaction_id: str):
        """处理 MAC 验证"""
        their_mac = content.get("mac") or {}
        their_keys = content.get("keys")

        logger.debug(f"[E2EE-Verify] 收到 MAC: keys={their_keys}")

        session = self._sessions.get(transaction_id, {})
        self._record_mac_received(session, their_mac)

        established_sas = session.get("established_sas")
        their_device = session.get("from_device", session.get("their_device", ""))
        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")
        sas_bytes = session.get("sas_bytes", b"\x00" * 32)

        if not isinstance(their_mac, dict) or not their_mac:
            await self._abort_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
            )
            return

        available_keys = await self._collect_mac_verification_keys(
            session,
            sender,
            their_device,
        )

        if not their_device or not available_keys:
            await self._abort_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
            )
            return

        key_ids = sorted(their_mac.keys())
        if not self._check_mac_key_ids(their_mac, key_ids, available_keys):
            await self._abort_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
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
            await self._abort_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
            )
            return
        expected_mac_map, expected_keys_mac = expected

        if not isinstance(their_keys, str):
            await self._abort_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
            )
            return

        if not self._verify_their_macs(their_mac, key_ids, expected_mac_map):
            await self._abort_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
            )
            return

        if not self._verify_keys_mac(their_keys, expected_keys_mac):
            await self._abort_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
            )
            return

        await self._complete_mac_verification(
            session,
            sender,
            their_device,
            transaction_id,
            is_in_room,
            room_id,
        )


__all__ = [
    "SASVerificationFlowMACFinishMixin",
    "SASVerificationFlowMACKeyCheckMixin",
    "SASVerificationFlowMACOrchestratorMixin",
    "SASVerificationFlowMACRecordMixin",
]

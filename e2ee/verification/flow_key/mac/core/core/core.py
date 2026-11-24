"""SAS MAC verification orchestration."""

from astrbot.api import logger

from .finish import SASVerificationFlowMACFinishMixin
from .guard import SASVerificationFlowMACGuardMixin
from .info import SASVerificationFlowMACInfoMixin
from .keycheck import SASVerificationFlowMACKeyCheckMixin
from .record import SASVerificationFlowMACRecordMixin


class SASVerificationFlowMACOrchestratorMixin(
    SASVerificationFlowMACRecordMixin,
    SASVerificationFlowMACKeyCheckMixin,
    SASVerificationFlowMACFinishMixin,
    SASVerificationFlowMACGuardMixin,
    SASVerificationFlowMACInfoMixin,
):
    """校验对端 MAC 并在失败时发送取消。"""

    async def _handle_mac(self, sender: str, content: dict, transaction_id: str):
        """处理 MAC 验证"""
        from_device = content.get("from_device")
        session = self._get_bound_verification_session(
            transaction_id,
            sender,
            from_device,
        )
        if session is None:
            return

        their_device = session.get("from_device") or session.get("their_device", "")
        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")
        established_sas = session.get("established_sas")
        sas_bytes = session.get("sas_bytes")
        has_fallback_sas = (
            isinstance(sas_bytes, (bytes, bytearray))
            and bool(sas_bytes)
            and bool(session.get("sas_emojis") or session.get("sas_decimals"))
        )

        # MAC is method-specific traffic after both ephemeral keys have been
        # exchanged and the SAS has been derived. Never substitute zero bytes for
        # missing cryptographic state, and never accept a second peer MAC.
        if (
            session.get("state") != "key_exchanged"
            or not session.get("their_key")
            or not session.get("key_sent")
            or (established_sas is None and not has_fallback_sas)
            or session.get("their_mac") is not None
        ):
            await self._reject_unexpected_verification_event(
                session,
                transaction_id,
                "m.key.verification.mac",
                sender=sender,
                from_device=from_device or their_device,
            )
            return

        their_mac = content.get("mac")
        their_keys = content.get("keys")
        if (
            not isinstance(their_mac, dict)
            or not their_mac
            or not all(
                isinstance(key_id, str)
                and key_id
                and isinstance(value, str)
                and value
                for key_id, value in their_mac.items()
            )
            or not isinstance(their_keys, str)
            or not their_keys
        ):
            await self._cancel_bound_verification_session(
                session,
                transaction_id,
                "m.invalid_message",
                "Malformed SAS MAC event",
                sender=sender,
                from_device=from_device or their_device,
            )
            return

        logger.debug(f"[E2EE-Verify] 收到 MAC: keys={their_keys}")
        self._record_mac_received(session, their_mac)

        available_keys = await self._collect_mac_verification_keys(
            session,
            sender,
            their_device,
        )

        key_ids = sorted(their_mac.keys())
        if self._mac_guard_failure(their_mac, their_device, available_keys, key_ids):
            await self._abort_mac_verification(
                session,
                sender,
                their_device,
                is_in_room,
                room_id,
                transaction_id,
            )
            return

        base_info = self._build_mac_base_info(sender, their_device, transaction_id)
        key_ids_csv = self._build_mac_key_ids_csv(key_ids)

        expected = await self._compute_expected_macs(
            session,
            bytes(sas_bytes or b""),
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
    "SASVerificationFlowMACGuardMixin",
    "SASVerificationFlowMACInfoMixin",
    "SASVerificationFlowMACKeyCheckMixin",
    "SASVerificationFlowMACOrchestratorMixin",
    "SASVerificationFlowMACRecordMixin",
]

"""Megolm session import for m.room_key events."""

from astrbot.api import logger


class E2EEManagerDecryptRoomKeyImportMixin:
    """Import a Megolm inbound session and report the outcome."""

    def _import_room_key_session(
        self,
        room_id,
        session_id,
        session_key,
        original_sender_key,
        claimed_keys,
        stored_forwarding_chain,
        shared_history,
        sender_user_id,
        forwarded,
        withheld,
    ):
        imported = self._olm.add_megolm_inbound_session(
            room_id,
            session_id,
            session_key,
            original_sender_key,
            claimed_keys,
            stored_forwarding_chain,
            shared_history,
            None if forwarded else sender_user_id,
            withheld if forwarded else {},
        )
        if imported is False:
            logger.warning(
                f"Failed to import the Megolm key for room {room_id}; "
                "keeping the room-key request pending"
            )
            return False
        logger.info(f"收到房间 {room_id} 的 Megolm 密钥")
        return True


__all__ = ["E2EEManagerDecryptRoomKeyImportMixin"]

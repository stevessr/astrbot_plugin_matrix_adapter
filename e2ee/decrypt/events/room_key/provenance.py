"""Room-key provenance validation (forwarded vs direct)."""

from astrbot.api import logger

from ....constants import (
    VALID_WITHHELD_CODES,
    WITHHELD_NO_OLM,
)


class E2EEManagerDecryptRoomKeyProvenanceMixin:
    """Validate the authenticated origin of a received room key."""

    async def _validate_room_key_provenance(
        self,
        event,
        sender_key,
        sender_user_id,
        forwarded,
    ) -> tuple[list, str, str | None, dict | None] | None:
        """Return (forwarding_chain, original_sender_key, forwarded_ed25519,
        withheld) or None when the provenance is rejected."""
        withheld = None
        if forwarded:
            forwarded_chain = event.get("forwarding_curve25519_key_chain")
            original_sender_key = event.get("sender_key")
            forwarded_ed25519 = event.get("sender_claimed_ed25519_key")
            if (
                sender_user_id != self.user_id
                or not isinstance(forwarded_chain, list)
                or not all(isinstance(key, str) and key for key in forwarded_chain)
                or not isinstance(original_sender_key, str)
                or not original_sender_key
                or not isinstance(forwarded_ed25519, str)
                or not forwarded_ed25519
            ):
                logger.warning("Rejected malformed or cross-user forwarded room key")
                return None

            source = await self._find_device_by_sender_key(
                sender_key,
                sender_user_id,
            )
            if not source or source[0] != self.user_id:
                logger.warning("Rejected forwarded room key from an unknown device")
                return None
            source_device = source[1]
            device_info = await self._get_validated_device_info(
                self.user_id,
                source_device,
            )
            if not device_info or not await self._is_own_device_trusted(
                source_device,
                device_info,
            ):
                logger.warning("Rejected forwarded room key from an unverified device")
                return None

            raw_withheld = event.get("withheld")
            if raw_withheld is not None:
                if (
                    not isinstance(raw_withheld, dict)
                    or raw_withheld.get("code") not in VALID_WITHHELD_CODES
                    or raw_withheld.get("code") == WITHHELD_NO_OLM
                    or not isinstance(raw_withheld.get("reason"), str)
                ):
                    logger.warning("Rejected malformed forwarded-key withheld data")
                    return None
                withheld = {
                    "code": raw_withheld["code"],
                    "reason": raw_withheld["reason"],
                }
        else:
            if not isinstance(sender_user_id, str) or not sender_user_id:
                logger.warning("Rejected room key without an authenticated sender")
                return None
            forwarded_chain = []
            original_sender_key = sender_key
            forwarded_ed25519 = None

        return forwarded_chain, original_sender_key, forwarded_ed25519, withheld

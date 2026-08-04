"""Provenance metadata validation for room-key forwarding."""

from astrbot.api import logger

from ....constants import WITHHELD_UNAVAILABLE


class E2EEManagerRequestsRespondProvenanceMixin:
    """Validate authenticated session provenance before forwarding."""

    async def _load_provenance(
        self,
        sender: str,
        requesting_device_id: str,
        room_id: str,
        session_id: str,
    ):
        """Load and validate provenance metadata for the requested session.

        Returns a (sender_key, claimed_ed25519, forwarding_chain, withheld)
        tuple, or None when the metadata is missing or invalid.
        """
        metadata = None
        get_metadata = getattr(
            self._store,
            "get_megolm_inbound_metadata",
            None,
        )
        if callable(get_metadata):
            metadata = get_metadata(session_id)
        if not isinstance(metadata, dict) or metadata.get("room_id") != room_id:
            logger.warning(
                "Refusing room-key forwarding without matching authenticated "
                "session metadata"
            )
            await self._send_room_key_withheld(
                sender,
                requesting_device_id,
                room_id,
                session_id,
                WITHHELD_UNAVAILABLE,
                "The requested room key has no validated provenance metadata",
            )
            return None

        # RequestedKeyInfo.sender_key is deprecated and MUST NOT be used to
        # locate or establish provenance for a session.
        original_sender_key = metadata.get("sender_key")
        if not isinstance(original_sender_key, str) or not original_sender_key:
            await self._send_room_key_withheld(
                sender,
                requesting_device_id,
                room_id,
                session_id,
                WITHHELD_UNAVAILABLE,
                "The requested room key has incomplete provenance metadata",
            )
            return None
        claimed_keys = metadata.get("sender_claimed_keys")
        if not isinstance(claimed_keys, dict):
            claimed_keys = {}
        original_ed25519 = claimed_keys.get("ed25519")
        if not isinstance(original_ed25519, str) or not original_ed25519:
            await self._send_room_key_withheld(
                sender,
                requesting_device_id,
                room_id,
                session_id,
                WITHHELD_UNAVAILABLE,
                "The requested room key has incomplete claimed-key metadata",
            )
            return None

        forwarding_chain = metadata.get("forwarding_curve25519_key_chain")
        if not isinstance(forwarding_chain, list):
            forwarding_chain = []
        forwarding_chain = [key for key in forwarding_chain if isinstance(key, str)]

        return original_sender_key, original_ed25519, forwarding_chain, metadata

import hashlib

from ...constants import MEGOLM_MESSAGE_INDEX_FIELD


class E2EEManagerDecryptMegolmValidateMixin:
    async def _validate_incoming_megolm_plaintext(
        self,
        plaintext: object,
        *,
        sender: str | None,
        room_id: str,
        session_id: str,
        ciphertext: str,
        event_id: str | None,
    ) -> bool:
        """Bind Megolm plaintext to its room, sender, session, and event index."""
        if not isinstance(plaintext, dict) or not isinstance(sender, str) or not sender:
            return False
        message_index = plaintext.pop(MEGOLM_MESSAGE_INDEX_FIELD, None)
        if plaintext.get("room_id") != room_id:
            return False
        if not isinstance(plaintext.get("type"), str) or not plaintext.get("type"):
            return False
        if not isinstance(plaintext.get("content"), dict):
            return False

        get_metadata = getattr(self._store, "get_megolm_inbound_metadata", None)
        metadata = get_metadata(session_id) if callable(get_metadata) else None
        if not isinstance(metadata, dict) or metadata.get("room_id") != room_id:
            return False
        bound_sender = metadata.get("sender_user_id")
        if isinstance(bound_sender, str) and bound_sender:
            if bound_sender != sender:
                return False
        else:
            sender_curve = metadata.get("sender_key")
            claimed_keys = metadata.get("sender_claimed_keys")
            sender_ed25519 = (
                claimed_keys.get("ed25519") if isinstance(claimed_keys, dict) else None
            )
            if not isinstance(sender_curve, str) or not isinstance(
                sender_ed25519,
                str,
            ):
                return False

            candidates = {}
            if self._store:
                get_all = getattr(self._store, "get_all_device_keys", None)
                if callable(get_all):
                    all_keys = get_all()
                    if isinstance(all_keys, dict):
                        candidates = all_keys.get(sender) or {}
            matching = self._find_validated_sender_device(
                sender,
                sender_curve,
                sender_ed25519,
                candidates,
            )
            if not matching:
                try:
                    response = await self.client.query_keys({sender: []})
                except Exception:
                    return False
                candidates = (response.get("device_keys") or {}).get(sender) or {}
                matching = self._find_validated_sender_device(
                    sender,
                    sender_curve,
                    sender_ed25519,
                    candidates,
                )
                if not matching:
                    return False

            bind_sender = getattr(
                self._store,
                "bind_megolm_inbound_sender_user",
                None,
            )
            if callable(bind_sender) and not bind_sender(session_id, sender):
                return False

        if message_index is None:
            # Compatibility with test/custom Olm implementations which do not
            # expose the vodozemac message index. Production always does.
            return True
        check_replay = getattr(
            self._store,
            "check_and_record_megolm_message_index",
            None,
        )
        if not callable(check_replay):
            return False
        identifier = (
            event_id
            if isinstance(event_id, str) and event_id
            else hashlib.sha256(ciphertext.encode("utf-8")).hexdigest()
        )
        return bool(check_replay(session_id, message_index, identifier))

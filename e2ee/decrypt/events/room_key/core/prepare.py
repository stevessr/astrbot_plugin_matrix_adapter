"""Import-parameter preparation for m.room_key events."""


class E2EEManagerDecryptRoomKeyPrepareMixin:
    """Compute shared-history and forwarding-chain import parameters."""

    def _compute_import_provenance(self, event, sender_key, forwarded, forwarded_chain):
        # Only a direct m.room_key can declare shareability. A forwarded key
        # lacks this authenticated assertion and is therefore conservative.
        shared_history = not forwarded and event.get("shared_history") is True
        stored_forwarding_chain = list(forwarded_chain)
        if (
            forwarded
            and isinstance(sender_key, str)
            and sender_key
            and (
                not stored_forwarding_chain or stored_forwarding_chain[-1] != sender_key
            )
        ):
            # The content omits its current Olm sender. Persist that device as
            # the newest hop so a subsequent forward retains full provenance.
            stored_forwarding_chain.append(sender_key)
        return shared_history, stored_forwarding_chain


__all__ = ["E2EEManagerDecryptRoomKeyPrepareMixin"]

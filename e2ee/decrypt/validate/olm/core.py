"""Olm plaintext validation orchestration."""


class E2EEManagerDecryptOlmValidateOrchestratorMixin:
    """Apply Matrix v1.19/MSC4147 mandatory Olm plaintext checks."""

    async def _validate_incoming_olm_plaintext(
        self,
        plaintext: object,
        event_sender: str | None,
        sender_curve25519_key: str,
    ) -> bool:
        """Apply Matrix v1.19/MSC4147 mandatory Olm plaintext checks."""
        resolved = self._extract_olm_plaintext_claims(
            plaintext,
            event_sender,
            sender_curve25519_key,
        )
        if resolved is False:
            return False
        claimed_ed25519, sender_device_keys = resolved
        if sender_device_keys is not None:
            return self._validate_olm_sender_device_keys(
                event_sender,
                sender_curve25519_key,
                claimed_ed25519,
                sender_device_keys,
            )
        return await self._validate_olm_legacy_sender(
            event_sender,
            sender_curve25519_key,
            claimed_ed25519,
        )


__all__ = ["E2EEManagerDecryptOlmValidateOrchestratorMixin"]

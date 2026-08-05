"""Decrypted Olm payload parsing and validation."""

import json


class E2EEManagerDecryptOlmParseMixin:
    """Parse and validate the decrypted Olm plaintext."""

    async def _parse_decrypted_olm_payload(
        self,
        plaintext,
        *,
        sender: str | None,
        sender_key: str,
    ) -> dict | None:
        """Return the parsed payload, or ``None`` when the binding is invalid."""
        # 解析 JSON
        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode("utf-8")

        decrypted = json.loads(plaintext)
        if not await self._validate_incoming_olm_plaintext(
            decrypted,
            sender,
            sender_key,
        ):
            return None
        return decrypted


__all__ = ["E2EEManagerDecryptOlmParseMixin"]

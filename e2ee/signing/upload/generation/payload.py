"""Cross-signing key payload construction and signing."""


class CrossSigningUploadPayloadMixin:
    """Build and sign the cross-signing key payloads."""

    def _build_cross_signing_payloads(self) -> tuple:
        """Build master, self-signing, and user-signing key dicts."""
        master_key = {
            "user_id": self.user_id,
            "usage": ["master"],
            "keys": {f"ed25519:{self._master_key}": self._master_key},
        }
        self_signing_key = {
            "user_id": self.user_id,
            "usage": ["self_signing"],
            "keys": {f"ed25519:{self._self_signing_key}": self._self_signing_key},
        }
        user_signing_key = {
            "user_id": self.user_id,
            "usage": ["user_signing"],
            "keys": {f"ed25519:{self._user_signing_key}": self._user_signing_key},
        }
        return master_key, self_signing_key, user_signing_key

    def _sign_cross_signing_payloads(
        self,
        master_key: dict,
        self_signing_key: dict,
        user_signing_key: dict,
    ) -> None:
        """Sign each key payload with the master private key."""
        sig_master = self._sign(self._master_priv, master_key)
        master_key["signatures"] = {
            self.user_id: {f"ed25519:{self._master_key}": sig_master}
        }

        sig_self = self._sign(self._master_priv, self_signing_key)
        self_signing_key["signatures"] = {
            self.user_id: {f"ed25519:{self._master_key}": sig_self}
        }

        sig_user = self._sign(self._master_priv, user_signing_key)
        user_signing_key["signatures"] = {
            self.user_id: {f"ed25519:{self._master_key}": sig_user}
        }


__all__ = ["CrossSigningUploadPayloadMixin"]

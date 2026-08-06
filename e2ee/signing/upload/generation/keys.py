"""Cross-signing keypair generation."""


class CrossSigningUploadKeysMixin:
    """Generate fresh cross-signing keypairs."""

    def _generate_cross_signing_keys(
        self,
        force_regen: bool = False,
        reuse_master: bool = False,
    ) -> None:
        """Generate missing or forced keypairs."""
        if not self._master_priv or force_regen or not reuse_master:
            self._master_priv, self._master_key = self._gen_keypair()
        if not self._self_signing_priv or force_regen:
            self._self_signing_priv, self._self_signing_key = self._gen_keypair()
        if not self._user_signing_priv or force_regen:
            self._user_signing_priv, self._user_signing_key = self._gen_keypair()


__all__ = ["CrossSigningUploadKeysMixin"]
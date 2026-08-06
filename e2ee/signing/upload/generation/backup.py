"""Cross-signing key snapshot and restore."""


class CrossSigningUploadBackupMixin:
    """Snapshot and restore the previous cross-signing keys."""

    def _snapshot_cross_signing_keys(self) -> tuple:
        """保存旧密钥，以便上传失败时恢复。"""
        return (
            self._master_priv,
            self._master_key,
            self._self_signing_priv,
            self._self_signing_key,
            self._user_signing_priv,
            self._user_signing_key,
        )

    def _restore_cross_signing_keys(self, snapshot: tuple) -> None:
        """恢复旧密钥。"""
        (
            self._master_priv,
            self._master_key,
            self._self_signing_priv,
            self._self_signing_key,
            self._user_signing_priv,
            self._user_signing_key,
        ) = snapshot


__all__ = ["CrossSigningUploadBackupMixin"]
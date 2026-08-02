"""Public KeyBackup properties and Secret Storage adapters."""


class KeyBackupPropertiesMixin:
    @property
    def backup_version(self) -> str | None:
        return self._backup_version

    @property
    def recovery_key_bytes(self) -> bytes | None:
        return self._recovery_key_bytes

    @property
    def secret_storage_key_bytes(self) -> bytes | None:
        return self.get_secret_storage_key_bytes()

    def load_extracted_key(self) -> bytes | None:
        return self._load_extracted_key()

    async def read_ssss_secret(self, secret_name: str) -> bytes | None:
        return await self.read_secret_from_secret_storage(secret_name)

    async def write_ssss_secret(
        self, secret_name: str, secret_value: bytes | str
    ) -> bool:
        return await self.write_secret_to_secret_storage(secret_name, secret_value)

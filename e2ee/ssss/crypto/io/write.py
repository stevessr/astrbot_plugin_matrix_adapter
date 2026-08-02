"""Write encrypted Secret Storage account data."""

from astrbot.api import logger


class KeyBackupSSSSStorageIOWriteMixin:
    async def write_secret_to_secret_storage(
        self,
        secret_name: str,
        secret_value: bytes | str,
        key_bytes: bytes | None = None,
    ) -> bool:
        try:
            context = await self._resolve_secret_storage_context(
                key_bytes=key_bytes,
                create_if_missing=True,
            )
            if not context:
                return False

            key_id, ssss_key = context
            plaintext = (
                secret_value.encode("utf-8")
                if isinstance(secret_value, str)
                else bytes(secret_value)
            )

            existing = await self.client.get_global_account_data(secret_name) or {}
            if not isinstance(existing, dict):
                existing = {}

            encrypted_map = existing.get("encrypted")
            if not isinstance(encrypted_map, dict):
                encrypted_map = {}

            encrypted_map[key_id] = self._encrypt_ssss_data(
                ssss_key,
                plaintext,
                secret_name=secret_name,
            )
            existing["encrypted"] = encrypted_map

            await self.client.set_global_account_data(secret_name, existing)
            return True
        except Exception as e:
            logger.warning(f"写入 Secret Storage 失败：secret={secret_name} error={e}")
            return False

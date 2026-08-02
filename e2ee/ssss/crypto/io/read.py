"""Read encrypted Secret Storage account data."""

from astrbot.api import logger


class KeyBackupSSSSStorageIOReadMixin:
    async def read_secret_from_secret_storage(
        self,
        secret_name: str,
        key_bytes: bytes | None = None,
    ) -> bytes | None:
        try:
            context = await self._resolve_secret_storage_context(
                key_bytes=key_bytes,
                create_if_missing=False,
            )
            if not context:
                return None

            key_id, ssss_key = context
            secret_data = await self.client.get_global_account_data(secret_name) or {}
            encrypted_map = secret_data.get("encrypted")
            if not isinstance(encrypted_map, dict):
                return None

            encrypted_data = encrypted_map.get(key_id)
            if not isinstance(encrypted_data, dict):
                logger.warning(
                    f"Account Data '{secret_name}' 中未找到 Key ID {key_id} 的加密数据"
                )
                return None

            return self._decrypt_ssss_data(
                ssss_key,
                encrypted_data,
                secret_name=secret_name,
            )
        except Exception as e:
            logger.error(
                f"读取 Secret Storage 中的 secret 失败：{secret_name} error={e}"
            )
            return None

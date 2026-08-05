"""Secret Storage persistence of cross-signing private keys."""

import base64

from .....constants import (
    SECRET_CROSS_SIGNING_MASTER,
    SECRET_CROSS_SIGNING_SELF_SIGNING,
    SECRET_CROSS_SIGNING_USER_SIGNING,
)


class CrossSigningRestoreSecretsWriteMixin:
    """将交叉签名私钥写入 Secret Storage。"""

    async def _write_private_keys_to_secret_storage(self) -> bool | None:
        if not self.secret_storage:
            return None

        secrets_to_write = {
            SECRET_CROSS_SIGNING_MASTER: self._master_priv,
            SECRET_CROSS_SIGNING_SELF_SIGNING: self._self_signing_priv,
            SECRET_CROSS_SIGNING_USER_SIGNING: self._user_signing_priv,
        }

        wrote_any = False
        for secret_name, secret_bytes in secrets_to_write.items():
            if not secret_bytes:
                continue
            payload = base64.b64encode(secret_bytes).decode("utf-8")
            try:
                write_ok = await self.secret_storage.write_ssss_secret(
                    secret_name, payload
                )
            except AttributeError:
                write_ok = await self.secret_storage.write_secret_to_secret_storage(
                    secret_name,
                    payload,
                )
            if not write_ok:
                return False
            wrote_any = True

        return True if wrote_any else None


__all__ = ["CrossSigningRestoreSecretsWriteMixin"]

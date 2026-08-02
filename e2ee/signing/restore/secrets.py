"""Secret Storage recovery and persistence for cross-signing keys."""

import base64

from astrbot.api import logger

from ....constants import (
    SECRET_CROSS_SIGNING_MASTER,
    SECRET_CROSS_SIGNING_SELF_SIGNING,
    SECRET_CROSS_SIGNING_USER_SIGNING,
)


class CrossSigningRestoreSecretsMixin:
    """从 Secret Storage 恢复并写入交叉签名私钥。"""

    async def _restore_private_keys_from_secret_storage(
        self,
        server_master: str | None,
        server_self_signing: str | None,
        server_user_signing: str | None,
    ) -> bool:
        if not self.secret_storage:
            return False

        secret_map = {
            SECRET_CROSS_SIGNING_MASTER: ("_master_priv", "_master_key", server_master),
            SECRET_CROSS_SIGNING_SELF_SIGNING: (
                "_self_signing_priv",
                "_self_signing_key",
                server_self_signing,
            ),
            SECRET_CROSS_SIGNING_USER_SIGNING: (
                "_user_signing_priv",
                "_user_signing_key",
                server_user_signing,
            ),
        }

        restored_any = False
        for secret_name, (priv_attr, pub_attr, server_pub) in secret_map.items():
            current_priv = getattr(self, priv_attr)
            if current_priv:
                derived_current = self._derive_public_key(current_priv)
                if not server_pub or derived_current == server_pub:
                    continue

            try:
                secret_bytes = await self.secret_storage.read_ssss_secret(secret_name)
            except AttributeError:
                secret_bytes = (
                    await self.secret_storage.read_secret_from_secret_storage(
                        secret_name
                    )
                )

            decoded = self._decode_secret_bytes(secret_bytes or b"")
            if not decoded:
                continue

            derived_pub = self._derive_public_key(decoded)
            expected_pub = server_pub or derived_pub
            if expected_pub and derived_pub and derived_pub != expected_pub:
                logger.warning(
                    f"[E2EE-CrossSign] 从 SSSS 恢复的 {secret_name} 与服务器公钥不匹配，忽略"
                )
                continue

            setattr(self, priv_attr, decoded)
            if expected_pub:
                setattr(self, pub_attr, expected_pub)
            restored_any = True

        if restored_any:
            self._save_local_keys()
            logger.info("[E2EE-CrossSign] 已从 Secret Storage 恢复 cross-signing 私钥")

        return restored_any

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

"""Cross-signing key generation and upload orchestration."""

from astrbot.api import logger

from ...backup.crypto_utils import CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE
from .compat import resolve_upload_symbol


class CrossSigningUploadGenerationMixin:
    """生成、上传并持久化交叉签名密钥。"""

    async def _generate_and_upload_keys(
        self, force_regen: bool = False, reuse_master: bool = False
    ):
        if not resolve_upload_symbol("CRYPTO_AVAILABLE", _DEFAULT_CRYPTO_AVAILABLE):
            return

        # 保存旧密钥，以便上传失败时恢复
        old_master_priv = self._master_priv
        old_master_key = self._master_key
        old_self_signing_priv = self._self_signing_priv
        old_self_signing_key = self._self_signing_key
        old_user_signing_priv = self._user_signing_priv
        old_user_signing_key = self._user_signing_key

        if not self._master_priv or force_regen or not reuse_master:
            self._master_priv, self._master_key = self._gen_keypair()
        if not self._self_signing_priv or force_regen:
            self._self_signing_priv, self._self_signing_key = self._gen_keypair()
        if not self._user_signing_priv or force_regen:
            self._user_signing_priv, self._user_signing_key = self._gen_keypair()

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

        try:
            await self._upload_signing_keys_with_uia(
                master_key=master_key,
                self_signing_key=self_signing_key,
                user_signing_key=user_signing_key,
            )
        except Exception:
            self._restore_keys(
                old_master_priv,
                old_master_key,
                old_self_signing_priv,
                old_self_signing_key,
                old_user_signing_priv,
                old_user_signing_key,
            )
            raise

        self._save_local_keys()
        ssss_status = await self._write_private_keys_to_secret_storage()
        logger.info("[E2EE-CrossSign] 已生成并上传交叉签名密钥")
        if ssss_status is False:
            logger.warning(
                "[E2EE-CrossSign] public cross-signing keys 上传成功，但写入 Secret Storage 失败；"
                "已保留新的本地私钥，不回滚服务器状态"
            )
        elif ssss_status is True:
            logger.info("[E2EE-CrossSign] 已将 cross-signing 私钥写入 Secret Storage")

    async def upload_cross_signing_keys(self):
        if (
            not self._master_priv
            or not self._self_signing_priv
            or not self._user_signing_priv
        ):
            await self._generate_and_upload_keys(force_regen=True)
            return
        await self._generate_and_upload_keys(force_regen=False, reuse_master=True)

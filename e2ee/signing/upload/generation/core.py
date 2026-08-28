"""Cross-signing key generation and upload orchestration."""

from astrbot.api import logger

from .backup import CrossSigningUploadBackupMixin
from .guard import CrossSigningUploadGuardMixin
from .keys import CrossSigningUploadKeysMixin
from .payload import CrossSigningUploadPayloadMixin


class CrossSigningUploadGenerationMixin(
    CrossSigningUploadGuardMixin,
    CrossSigningUploadBackupMixin,
    CrossSigningUploadKeysMixin,
    CrossSigningUploadPayloadMixin,
):
    """生成、上传并持久化交叉签名密钥。"""

    async def _generate_and_upload_keys(
        self, force_regen: bool = False, reuse_master: bool = False
    ):
        if not self._cross_signing_upload_ready():
            return

        # 保存旧密钥，以便上传失败时恢复
        snapshot = self._snapshot_cross_signing_keys()

        self._generate_cross_signing_keys(force_regen, reuse_master)

        (
            master_key,
            self_signing_key,
            user_signing_key,
        ) = self._build_cross_signing_payloads()
        self._sign_cross_signing_payloads(
            master_key,
            self_signing_key,
            user_signing_key,
        )

        try:
            await self._upload_signing_keys_with_uia(
                master_key=master_key,
                self_signing_key=self_signing_key,
                user_signing_key=user_signing_key,
            )
        except Exception:
            self._restore_cross_signing_keys(snapshot)
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


__all__ = [
    "CrossSigningUploadBackupMixin",
    "CrossSigningUploadGenerationMixin",
    "CrossSigningUploadGuardMixin",
    "CrossSigningUploadKeysMixin",
    "CrossSigningUploadPayloadMixin",
]

"""Master-key device-signing orchestration."""

from astrbot.api import logger

from ......client.http_client import MatrixAPIError


class CrossSigningMasterSignOrchestratorMixin:
    """为当前账号 master key 上传当前设备签名。"""

    async def sign_master_key_with_device(self, user_id: str | None = None) -> bool:
        target_user_id = user_id or self.user_id
        if target_user_id != self.user_id:
            logger.debug("[E2EE-CrossSign] 仅支持为当前账号的 master key 添加设备签名")
            return False
        if not self.olm or not self._master_key:
            logger.debug(
                "[E2EE-CrossSign] master key 或 olm 账户不可用，跳过设备签名 master key"
            )
            return False

        try:
            context = await self._load_current_master_signing_context(target_user_id)
            prepared = self._prepare_master_signature_payload(target_user_id, context)
            if prepared is None:
                return False
            if prepared is True:
                return True
            master_key_to_upload, signing_key_id, master_pubkey_b64 = prepared

            ok = await self._upload_signature_and_confirm(
                {target_user_id: {master_pubkey_b64: master_key_to_upload}},
                lambda: self._verify_uploaded_master_signature(
                    target_user_id, signing_key_id
                ),
                "master key 设备签名 ",
            )
            if not ok:
                return False

            logger.debug("[E2EE-CrossSign] 已为 master key 添加设备签名")
            return True
        except MatrixAPIError as e:
            logger.warning(f"[E2EE-CrossSign] master key 设备签名失败：{e}")
            return False
        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] master key 设备签名异常：{e}")
            return False


__all__ = ["CrossSigningMasterSignOrchestratorMixin"]

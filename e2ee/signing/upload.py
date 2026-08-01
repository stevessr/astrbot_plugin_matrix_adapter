import asyncio
import copy

from astrbot.api import logger

from ...client.http_client import MatrixAPIError
from ...constants import LOGIN_TYPE_DUMMY, LOGIN_TYPE_PASSWORD
from ..key_backup_crypto import CRYPTO_AVAILABLE


class CrossSigningUploadMixin:
    """生成与上传密钥"""

    async def _upload_signing_keys_with_uia(
        self,
        *,
        master_key: dict,
        self_signing_key: dict,
        user_signing_key: dict,
    ) -> None:
        try:
            await self.client.upload_signing_keys(
                master_key=master_key,
                self_signing_key=self_signing_key,
                user_signing_key=user_signing_key,
            )
            return
        except MatrixAPIError as first_error:
            session_id = self._extract_uia_session(first_error)
            if not session_id:
                raise

            try:
                await self.client.upload_signing_keys(
                    master_key=master_key,
                    self_signing_key=self_signing_key,
                    user_signing_key=user_signing_key,
                    auth={"type": LOGIN_TYPE_DUMMY, "session": session_id},
                )
                return
            except MatrixAPIError as dummy_error:
                session_id = self._extract_uia_session(dummy_error) or session_id
                if not self.password:
                    logger.warning(
                        "[E2EE-CrossSign] 上传交叉签名密钥失败（未配置 matrix_password）"
                    )
                    raise

                await self.client.upload_signing_keys(
                    master_key=master_key,
                    self_signing_key=self_signing_key,
                    user_signing_key=user_signing_key,
                    auth=self._build_password_auth(session_id),
                )

    async def _repair_current_device_keys_once(self) -> bool:
        if not self.repair_current_device_keys:
            return False
        try:
            await self.repair_current_device_keys()
            return True
        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] 重新上传当前设备密钥失败：{e}")
            return False

    async def _republish_current_device_keys(self) -> None:
        if not hasattr(self.client, "upload_keys"):
            return
        try:
            response = await self.client.query_keys({self.user_id: [self.device_id]})
            device_keys = (
                (response.get("device_keys") or {})
                .get(self.user_id, {})
                .get(self.device_id)
            )
            if not isinstance(device_keys, dict) or not device_keys:
                return

            signing_key_id = (
                f"ed25519:{self._self_signing_key}"
                if isinstance(self._self_signing_key, str) and self._self_signing_key
                else None
            )
            existing_signatures = (device_keys.get("signatures") or {}).get(
                self.user_id, {}
            ) or {}
            if signing_key_id and signing_key_id in existing_signatures:
                logger.debug(
                    "[E2EE-CrossSign] 当前设备已存在 owner-sign，跳过重复重发布 device_keys"
                )
                return

            republish_payload = copy.deepcopy(device_keys)
            republish_payload.pop("unsigned", None)
            if republish_payload == device_keys:
                logger.debug(
                    "[E2EE-CrossSign] 当前设备 device_keys 已与服务器一致，跳过重复上传"
                )
                return

            await self.client.upload_keys(device_keys=republish_payload)
            logger.debug(
                "[E2EE-CrossSign] 已重发布当前设备的 device_keys 以刷新客户端缓存"
            )
        except Exception as e:
            logger.debug(f"[E2EE-CrossSign] 重发布当前设备 device_keys 失败：{e}")

    async def _upload_signature_and_confirm(
        self,
        upload_payload: dict,
        verify,
        failure_context: str,
    ) -> bool:
        upload_response = await self.client.upload_signatures(signatures=upload_payload)
        failures = (
            upload_response.get("failures")
            if isinstance(upload_response, dict)
            else None
        )
        if isinstance(failures, dict) and failures:
            logger.warning(
                f"[E2EE-CrossSign] {failure_context}上传被服务器拒绝：failures={failures}"
            )
            return False

        for _ in range(5):
            if await verify():
                return True
            await asyncio.sleep(1.0)

        logger.warning(f"[E2EE-CrossSign] {failure_context}未在服务器状态中出现")
        return False

    async def _generate_and_upload_keys(
        self, force_regen: bool = False, reuse_master: bool = False
    ):
        if not CRYPTO_AVAILABLE:
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
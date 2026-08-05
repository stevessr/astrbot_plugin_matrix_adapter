"""Device-signing orchestration for cross-signing."""

from astrbot.api import logger

from ......client.http_client import MatrixAPIError


class CrossSigningDeviceSignOrchestratorMixin:
    """为设备上传 self-signing 签名。"""

    async def sign_device(self, device_id: str) -> bool:
        if not self._device_sign_ready():
            return False
        try:
            signing_key_id = f"ed25519:{self._self_signing_key}"
            device_keys = await self._fetch_sign_target_device_keys(device_id)
            if device_keys is None:
                return False

            if self._existing_owner_signature(device_keys, signing_key_id):
                return True

            device_keys_to_upload = self._build_device_signature_payload(
                device_keys, signing_key_id
            )

            upload_payload = {self.user_id: {device_id: device_keys_to_upload}}
            ok = await self._upload_signature_and_confirm(
                upload_payload,
                lambda: self._verify_uploaded_device_signature(
                    device_id, signing_key_id
                ),
                f"设备签名 device={device_id} ",
            )
            if not ok:
                return False

            if device_id == self.device_id:
                await self._republish_current_device_keys()

            logger.debug(f"[E2EE-CrossSign] 已签名设备：{device_id}")
            return True
        except MatrixAPIError as e:
            logger.warning(f"[E2EE-CrossSign] 设备签名失败：{e}")
            return False
        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] 设备签名异常：{e}")
            return False


__all__ = ["CrossSigningDeviceSignOrchestratorMixin"]

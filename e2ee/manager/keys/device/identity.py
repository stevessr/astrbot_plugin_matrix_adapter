"""Device identity-key upload decision."""

from astrbot.api import logger


class E2EEManagerDeviceIdentityMixin:
    """Decide whether this device's identity keys need uploading."""

    async def _resolve_device_keys_to_upload(self):
        """Return device keys when the server lacks matching identity keys."""
        device_keys = None
        if self._olm.is_new_account:
            device_keys = self._olm.get_device_keys()
            logger.debug(
                f"新账户，准备上传设备密钥：device_id={device_keys.get('device_id')}"
            )
        else:
            try:
                verify_response = await self.client.query_keys({self.user_id: []})
                my_devices = (verify_response.get("device_keys") or {}).get(
                    self.user_id
                ) or {}
                if self.device_id not in my_devices:
                    device_keys = self._olm.get_device_keys()
                    logger.info(
                        f"服务器缺少设备 {self.device_id} 的身份密钥，准备重新上传"
                    )
                else:
                    server_device = my_devices[self.device_id]
                    server_keys = server_device.get("keys", {})
                    local_keys = self._olm.get_identity_keys()
                    if server_keys.get(f"ed25519:{self.device_id}") != local_keys.get(
                        f"ed25519:{self.device_id}"
                    ) or server_keys.get(
                        f"curve25519:{self.device_id}"
                    ) != local_keys.get(f"curve25519:{self.device_id}"):
                        device_keys = self._olm.get_device_keys()
                        logger.warning(
                            f"服务器上的设备 {self.device_id} 身份密钥与本地不一致，准备重新上传"
                        )
                    else:
                        logger.debug(
                            f"服务器已存在设备 {self.device_id} 的身份密钥，跳过重复上传"
                        )
            except Exception as verify_e:
                device_keys = self._olm.get_device_keys()
                logger.warning(f"检查设备密钥是否已存在失败，将重新上传：{verify_e}")
        return device_keys

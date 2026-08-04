"""Post-upload device-key verification."""

from astrbot.api import logger


class E2EEManagerDeviceVerifyMixin:
    """Confirm the server stores this device's identity keys correctly."""

    async def _verify_uploaded_device_keys(self):
        try:
            verify_response = await self.client.query_keys({self.user_id: []})
            my_devices = (verify_response.get("device_keys") or {}).get(
                self.user_id
            ) or {}
            if self.device_id in my_devices:
                my_device_info = my_devices[self.device_id]
                my_keys = my_device_info.get("keys", {})
                local_keys = self._olm.get_identity_keys()
                server_ed25519 = my_keys.get(f"ed25519:{self.device_id}")
                server_curve25519 = my_keys.get(f"curve25519:{self.device_id}")
                local_ed25519 = local_keys.get(f"ed25519:{self.device_id}")
                local_curve25519 = local_keys.get(f"curve25519:{self.device_id}")
                if (
                    server_ed25519 == local_ed25519
                    and server_curve25519 == local_curve25519
                ):
                    logger.info(
                        f"✅ 验证成功：服务器已确认设备 {self.device_id} 的密钥"
                    )
                else:
                    logger.error(
                        f"❌ 验证失败：服务器上的设备 {self.device_id} 密钥与本地不一致"
                    )
                    logger.error(
                        "设备密钥对比："
                        f" local_ed25519={local_ed25519}"
                        f" server_ed25519={server_ed25519}"
                        f" local_curve25519={local_curve25519}"
                        f" server_curve25519={server_curve25519}"
                    )
                logger.debug(f"服务器上的密钥：{list(my_keys.keys())}")
                signatures = my_device_info.get("signatures", {})
                logger.debug(f"服务器上的签名用户：{list(signatures.keys())}")
            else:
                logger.error(f"❌ 验证失败：服务器没有设备 {self.device_id} 的密钥！")
                logger.error(f"服务器上的设备列表：{list(my_devices.keys())}")
        except Exception as verify_e:
            logger.warning(f"验证设备密钥失败：{verify_e}")

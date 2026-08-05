"""Sender-key resolution from the homeserver."""

from astrbot.api import logger


class E2EEManagerDecryptDeviceServerMixin:
    """Query the server for a device matching the sender key."""

    async def _find_sender_device_on_server(
        self,
        sender_key: str,
        sender_user_id: str,
    ) -> tuple[str, str] | None:
        """Return ``(user_id, device_id)`` when matched, else ``None``."""
        try:
            logger.info(
                f"本地缓存中未找到 sender_key，正在查询 {sender_user_id} 的设备..."
            )
            response = await self.client.query_keys({sender_user_id: []})
            user_devices = (response.get("device_keys") or {}).get(sender_user_id) or {}

            for device_id, device_info in user_devices.items():
                if not self._olm.verify_device_keys(
                    sender_user_id,
                    device_id,
                    device_info,
                ):
                    logger.warning(
                        "Ignoring device with an invalid self-signature while "
                        f"resolving sender key: {sender_user_id}/{device_id}"
                    )
                    continue
                keys = device_info.get("keys", {})
                curve_key = keys.get(f"curve25519:{device_id}")

                # 缓存到本地
                if self._store:
                    self._store.save_device_keys(sender_user_id, device_id, device_info)
                    logger.debug(f"缓存设备密钥：{sender_user_id}/{device_id}")

                if curve_key == sender_key:
                    logger.info(
                        f"从服务器找到 sender_key 对应的设备：{sender_user_id}/{device_id}"
                    )
                    return (sender_user_id, device_id)

            logger.warning(
                f"服务器返回的设备中没有匹配的 sender_key：{(sender_key or '')[:8]}..."
            )
        except Exception as e:
            logger.warning(f"从服务器查询设备密钥失败：{e}")

        return None


__all__ = ["E2EEManagerDecryptDeviceServerMixin"]

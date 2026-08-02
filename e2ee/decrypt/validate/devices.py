from astrbot.api import logger


class E2EEManagerDecryptDeviceValidateMixin:
    def _find_validated_sender_device(
        self,
        user_id: str,
        curve25519_key: str,
        ed25519_key: str,
        candidates: object,
    ) -> tuple[str, dict] | None:
        if not isinstance(candidates, dict):
            return None
        for device_id, device_info in candidates.items():
            if not isinstance(device_id, str) or not self._olm.verify_device_keys(
                user_id,
                device_id,
                device_info,
            ):
                continue
            keys = device_info.get("keys", {})
            if (
                keys.get(f"curve25519:{device_id}") == curve25519_key
                and keys.get(f"ed25519:{device_id}") == ed25519_key
            ):
                return device_id, device_info
        return None

    async def _find_device_by_sender_key(
        self, sender_key: str, sender_user_id: str | None = None
    ) -> tuple[str, str] | None:
        """
        通过 sender_key 查找对应的用户和设备

        首先检查本地缓存，如果找不到则尝试从服务器查询。

        Args:
            sender_key: 发送者的 curve25519 密钥
            sender_user_id: 可选的发送者用户 ID（如果已知）

        Returns:
            (user_id, device_id) 元组，或 None
        """
        # 1. 首先从本地缓存查找
        if self._store:
            device_keys = self._store.get_all_device_keys()
            for user_id, devices in device_keys.items():
                for device_id, keys in devices.items():
                    if sender_user_id and user_id != sender_user_id:
                        continue
                    if not self._olm.verify_device_keys(user_id, device_id, keys):
                        continue
                    device_curve_key = keys.get("keys", {}).get(
                        f"curve25519:{device_id}"
                    )
                    if device_curve_key == sender_key:
                        return (user_id, device_id)

        # 2. 如果本地没有，且知道发送者用户 ID，则从服务器查询
        if sender_user_id:
            try:
                logger.info(
                    f"本地缓存中未找到 sender_key，正在查询 {sender_user_id} 的设备..."
                )
                response = await self.client.query_keys({sender_user_id: []})
                user_devices = (response.get("device_keys") or {}).get(
                    sender_user_id
                ) or {}

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
                        self._store.save_device_keys(
                            sender_user_id, device_id, device_info
                        )
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

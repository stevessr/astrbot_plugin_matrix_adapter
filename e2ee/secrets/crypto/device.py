"""Device-key lookup and local device-cache helpers for secret sharing."""

from astrbot.api import logger


class E2EEManagerSecretsDeviceMixin:
    """设备密钥查询、校验与本地缓存相关能力。"""

    @staticmethod
    def _mask_device_id(device_id: str | None) -> str:
        from ....utils.utils import mask_device_id

        return mask_device_id(device_id)

    async def _get_validated_device_info(
        self,
        user_id: str,
        device_id: str,
        *,
        force_query: bool = False,
    ) -> dict | None:
        """Return a complete device object after verifying its self-signature."""
        if not self._olm or not user_id or not device_id:
            return None

        if not force_query and self._store:
            get_all = getattr(self._store, "get_all_device_keys", None)
            if callable(get_all):
                all_keys = get_all()
                cached = (
                    (all_keys.get(user_id) or {}).get(device_id)
                    if isinstance(all_keys, dict)
                    else None
                )
                if self._olm.verify_device_keys(user_id, device_id, cached):
                    return cached

        try:
            response = await self.client.query_keys({user_id: [device_id]})
        except Exception as e:
            logger.warning(
                f"[E2EE-ToDevice] Device-key query failed for {user_id}/{device_id}: {e}"
            )
            return None
        device_info = (
            ((response.get("device_keys") or {}).get(user_id) or {}).get(device_id)
            if isinstance(response, dict)
            else None
        )
        if not self._olm.verify_device_keys(user_id, device_id, device_info):
            logger.warning(
                "[E2EE-ToDevice] Rejecting invalid signed device keys for "
                f"{user_id}/{device_id}"
            )
            return None
        if self._store:
            self._store.save_device_keys(user_id, device_id, device_info)
        return device_info

    async def _get_own_devices(self) -> list[str]:
        """获取自己的所有设备 ID"""
        try:
            response = await self.client.query_keys({self.user_id: []})
            device_keys = (response.get("device_keys") or {}).get(self.user_id) or {}
            return list(device_keys.keys())
        except Exception as e:
            logger.error(f"[E2EE-Secrets] 获取设备列表失败：{e}")
            return []

    async def _ensure_device_keys(self, user_id: str, device_ids: list[str]):
        """确保已获取指定设备的密钥"""
        try:
            # 当本地 store 不可用时，仍尝试向服务器查询（不做本地缓存）
            if not self._store:
                await self.client.query_keys({user_id: []})
                logger.debug(
                    f"[E2EE-Secrets] 本地存储不可用，已尝试从服务器查询设备密钥：{user_id}"
                )
                return

            # 检查是否已有这些设备的密钥
            missing_devices = []
            for device_id in device_ids:
                if not self._store.get_device_keys(user_id, device_id):
                    missing_devices.append(device_id)

            if missing_devices:
                # 查询缺失的设备密钥
                response = await self.client.query_keys({user_id: []})
                device_keys = (response.get("device_keys") or {}).get(user_id) or {}
                for device_id in missing_devices:
                    device_info = device_keys.get(device_id)
                    if device_info:
                        self._store.save_device_keys(user_id, device_id, device_info)
                logger.debug(
                    f"[E2EE-Secrets] 已查询设备密钥：{user_id}/{missing_devices}"
                )
        except Exception as e:
            logger.error(f"[E2EE-Secrets] 确保设备密钥失败：{e}")

"""Current-device key repair and republishing helpers."""

import copy

from astrbot.api import logger


class CrossSigningUploadDevicesMixin:
    """修复并重新发布当前设备身份密钥。"""

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

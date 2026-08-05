"""Device signature construction."""

import copy

from astrbot.api import logger


class CrossSigningDeviceSignPayloadMixin:
    """Build the signed device payload for upload."""

    def _existing_owner_signature(
        self,
        device_keys: dict,
        signing_key_id: str,
    ) -> bool:
        existing_signatures = (device_keys.get("signatures") or {}).get(
            self.user_id, {}
        ) or {}
        if signing_key_id in existing_signatures:
            logger.debug(
                f"[E2EE-CrossSign] 设备已存在 owner-sign，跳过重复上传："
                f"{device_keys.get('device_id')}"
            )
            return True
        return False

    def _build_device_signature_payload(
        self,
        device_keys: dict,
        signing_key_id: str,
    ) -> dict:
        device_keys_to_upload = copy.deepcopy(device_keys)
        device_keys_to_upload.pop("unsigned", None)
        sig = self._sign(self._self_signing_priv, device_keys_to_upload)
        # 仅包含本次自签名密钥的签名，不携带旧的签名，
        # 避免服务器重新验证旧签名导致 M_INVALID_SIGNATURE。
        device_keys_to_upload["signatures"] = {self.user_id: {signing_key_id: sig}}
        return device_keys_to_upload


__all__ = ["CrossSigningDeviceSignPayloadMixin"]

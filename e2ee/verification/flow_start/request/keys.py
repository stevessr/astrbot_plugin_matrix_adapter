"""Device fingerprint and master key lookup for verification requests."""

from astrbot.api import logger

from .....constants import PREFIX_ED25519


class SASVerificationFlowRequestKeysMixin:
    """查询验证请求对端设备的指纹与主签名密钥。"""

    async def _query_request_verification_keys(
        self,
        session: dict,
        sender: str,
        from_device: str,
    ):
        try:
            resp = await self.client.query_keys({sender: []})
            devices = resp.get("device_keys") or {}
            user_devices = devices.get(sender) or {}
            device_info = user_devices.get(from_device) or {}
            keys = device_info.get("keys") or {}
            fingerprint = keys.get(f"{PREFIX_ED25519}{from_device}")
            if fingerprint:
                session["fingerprint"] = fingerprint
                logger.debug(
                    "[E2EE-Verify] 已获取设备指纹："
                    f"device={self._mask_identifier(from_device)}"
                )
            else:
                logger.warning(
                    "[E2EE-Verify] 未找到设备指纹："
                    f"sender={self._mask_identifier(sender)} "
                    f"device={self._mask_identifier(from_device)}"
                )

            master_key_obj = (resp.get("master_keys") or {}).get(sender) or {}
            master_keys = master_key_obj.get("keys") or {}
            if master_keys:
                master_key_id, master_key = next(iter(master_keys.items()))
                session["master_key_id"] = master_key_id
                session["master_key"] = master_key
        except Exception as e:
            logger.warning(
                "[E2EE-Verify] 查询验证设备指纹失败："
                f"sender={self._mask_identifier(sender)} "
                f"device={self._mask_identifier(from_device)} err={e}"
            )

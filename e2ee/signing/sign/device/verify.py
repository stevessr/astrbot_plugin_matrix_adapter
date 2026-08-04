"""Upload verification for device cross-signing."""


class CrossSigningDeviceSignVerifyMixin:
    """确认设备签名已上传到服务器。"""

    async def _verify_uploaded_device_signature(
        self, device_id: str, signing_key_id: str
    ) -> bool:
        refreshed = await self.client.query_keys({self.user_id: [device_id]})
        refreshed_device_keys = (refreshed.get("device_keys") or {}).get(
            self.user_id, {}
        ).get(device_id) or {}
        refreshed_signatures = (refreshed_device_keys.get("signatures") or {}).get(
            self.user_id, {}
        )
        return signing_key_id in refreshed_signatures

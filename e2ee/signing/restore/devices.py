"""Cross-signing private-key requests from other devices."""

from astrbot.api import logger

from ...constants import (
    DEVICE_SECRET_REQUEST_FAILED,
    DEVICE_SECRET_REQUEST_NOT_NEEDED,
    DEVICE_SECRET_REQUEST_PENDING,
    DEVICE_SECRET_REQUEST_UNAVAILABLE,
)


class CrossSigningRestoreDevicesMixin:
    """向其他设备请求缺失的交叉签名私钥。"""

    async def _request_missing_private_keys_from_devices(
        self,
        server_master: str | None,
        server_self_signing: str | None,
        server_user_signing: str | None,
    ) -> str:
        if not self.request_secret_from_devices:
            return DEVICE_SECRET_REQUEST_UNAVAILABLE

        missing = self._missing_cross_signing_secret_names(
            server_master,
            server_self_signing,
            server_user_signing,
        )
        if not missing:
            return DEVICE_SECRET_REQUEST_NOT_NEEDED

        request_ids = []
        for secret_name in missing:
            if secret_name in self._pending_secret_requests:
                continue
            try:
                request_id = await self.request_secret_from_devices(secret_name)
            except Exception as e:
                logger.warning(
                    f"[E2EE-CrossSign] 向其他设备请求 secret 失败：name={secret_name} error={e}"
                )
                continue

            if request_id:
                self._pending_secret_requests.add(secret_name)
                request_ids.append(request_id)

        return (
            DEVICE_SECRET_REQUEST_PENDING
            if request_ids
            else DEVICE_SECRET_REQUEST_FAILED
        )

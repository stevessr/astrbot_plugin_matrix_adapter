"""Secret sharing after a validated request."""

from astrbot.api import logger


class E2EEManagerSecretsRequestShareMixin:
    """Fetch and send the requested secret."""

    async def _share_requested_secret(
        self,
        sender: str,
        requesting_device_id: str,
        request_id: str,
        name: str,
    ) -> bool:
        # 获取请求的秘密
        secret_value = await self._get_secret_for_sharing(name)
        if not secret_value:
            logger.warning(f"[E2EE-Secrets] 无法获取秘密：{name}")
            return False

        # 发送秘密给请求的设备
        await self._send_secret(
            target_user=sender,
            target_device=requesting_device_id,
            request_id=request_id,
            secret_name=name,
            secret_value=secret_value,
        )
        return True


__all__ = ["E2EEManagerSecretsRequestShareMixin"]

"""Handle incoming secret requests."""

from astrbot.api import logger


class E2EEManagerSecretsRequestOrchestratorMixin:
    """处理设备间秘密共享请求。"""

    async def handle_secret_request(
        self, sender: str, content: dict, sender_device: str
    ):
        """
        处理 m.secret.request 事件

        当其他设备（通常是同一用户的新设备）请求秘密时调用。
        只响应来自同一用户的已验证设备的请求。

        Args:
            sender: 发送者用户 ID
            content: 事件内容
            sender_device: 发送设备 ID
        """
        parsed = self._parse_secret_request(content, sender_device)
        if parsed is None:
            return
        action, requesting_device_id, request_id, name = parsed

        logger.info(
            f"[E2EE-Secrets] 收到秘密请求：action={action} name={name} "
            f"device={self._mask_device_id(requesting_device_id)} "
            f"request_id={self._mask_request_id(request_id)}"
        )

        # 只处理 request 动作（忽略 request_cancellation）
        if action != "request":
            if action == "request_cancellation":
                logger.debug(
                    "[E2EE-Secrets] 秘密请求已取消："
                    f"request_id={self._mask_request_id(request_id)}"
                )
            return

        if not self._check_secret_request_allowed(
            sender,
            requesting_device_id,
            request_id,
            name,
        ):
            return

        if not await self._verify_secret_request_device(
            sender,
            requesting_device_id,
        ):
            return

        await self._share_requested_secret(
            sender,
            requesting_device_id,
            request_id,
            name,
        )


__all__ = ["E2EEManagerSecretsRequestOrchestratorMixin"]

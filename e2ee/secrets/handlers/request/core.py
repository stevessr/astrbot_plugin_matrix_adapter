"""Handle incoming secret requests."""

from astrbot.api import logger

from ....constants import SUPPORTED_SECRET_NAMES


class E2EEManagerSecretsRequestCoreMixin:
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
        if not isinstance(content, dict):
            return
        action = content.get("action")
        # Prefer the authenticated sender_device from to-device metadata over
        # the unauthenticated requesting_device_id inside the event content
        # (defense-in-depth; the device is still verified later).
        requesting_device_id = sender_device or content.get(
            "requesting_device_id", sender_device
        )
        request_id = content.get("request_id", "")
        name = content.get("name", "")

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

        # 安全检查：只响应来自同一用户的请求
        if sender != self.user_id:
            logger.warning(
                f"[E2EE-Secrets] 拒绝来自其他用户的秘密请求：{sender} != {self.user_id}"
            )
            return

        if not all(
            isinstance(value, str) and value
            for value in (requesting_device_id, request_id, name)
        ):
            logger.warning("[E2EE-Secrets] Rejecting malformed secret request")
            return

        # 安全检查：不响应自己设备的请求
        if requesting_device_id == self.device_id:
            logger.debug("[E2EE-Secrets] 忽略来自自己设备的秘密请求")
            return

        if name not in SUPPORTED_SECRET_NAMES:
            logger.warning(f"[E2EE-Secrets] 不支持的秘密类型：{name}")
            return

        device_info = await self._get_validated_device_info(
            sender,
            requesting_device_id,
            force_query=True,
        )
        if not device_info or not await self._is_own_device_trusted(
            requesting_device_id,
            device_info,
        ):
            logger.warning(
                "[E2EE-Secrets] Rejecting secret request from unverified device: "
                f"{self._mask_device_id(requesting_device_id)}"
            )
            return

        # 获取请求的秘密
        secret_value = await self._get_secret_for_sharing(name)
        if not secret_value:
            logger.warning(f"[E2EE-Secrets] 无法获取秘密：{name}")
            return

        # 发送秘密给请求的设备
        await self._send_secret(
            target_user=sender,
            target_device=requesting_device_id,
            request_id=request_id,
            secret_name=name,
            secret_value=secret_value,
        )

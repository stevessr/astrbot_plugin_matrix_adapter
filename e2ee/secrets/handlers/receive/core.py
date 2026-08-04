"""Validate and process encrypted secret responses from other devices."""

from astrbot.api import logger


class E2EEManagerSecretsReceiveCoreMixin:
    """接收并处理设备间共享秘密。"""

    async def handle_secret_send(self, sender: str, content: dict, sender_key: str):
        """
        处理 m.secret.send 事件

        当收到其他设备发送的秘密时调用。

        Args:
            sender: 发送者用户 ID
            content: 事件内容（已解密）
            sender_key: Outer authenticated Olm Curve25519 sender key.
        """
        if not isinstance(content, dict):
            return

        request_id = content.get("request_id", "")
        secret = content.get("secret", "")

        logger.info(
            "[E2EE-Secrets] Received secret: "
            f"request_id={self._mask_request_id(request_id)} "
            f"secret_len={len(secret) if isinstance(secret, str) else 0}"
        )

        # 安全检查：只接受来自同一用户的秘密
        if sender != self.user_id:
            logger.warning(
                f"[E2EE-Secrets] 拒绝来自其他用户的秘密：{sender} != {self.user_id}"
            )
            return

        if not all(
            isinstance(value, str) and value
            for value in (request_id, secret, sender_key)
        ):
            logger.warning("[E2EE-Secrets] Rejecting malformed secret message")
            return

        source = await self._find_device_by_sender_key(sender_key, sender)
        if not source or source[0] != self.user_id:
            logger.warning("[E2EE-Secrets] Rejecting secret from unknown source device")
            return

        source_device = source[1]
        device_info = await self._get_validated_device_info(
            self.user_id,
            source_device,
        )
        if not device_info or not await self._is_own_device_trusted(
            source_device,
            device_info,
        ):
            logger.warning("[E2EE-Secrets] Rejecting secret from unverified device")
            return

        # 查找对应的待处理请求
        pending_request = self._get_pending_secret_request(request_id)
        if pending_request:
            secret_name = pending_request.get("name", "")
            await self._process_received_secret(secret_name, secret)
            self._remove_pending_secret_request(request_id)
        else:
            logger.debug(
                "[E2EE-Secrets] 未找到对应的待处理请求："
                f"{self._mask_request_id(request_id)}"
            )

"""Send encrypted secret responses to another device."""

from astrbot.api import logger

from ....constants import M_ROOM_ENCRYPTED, M_SECRET_SEND


class E2EEManagerSecretsSendMixin:
    """发送设备间共享秘密的加密响应。"""

    async def _send_secret(
        self,
        target_user: str,
        target_device: str,
        request_id: str,
        secret_name: str,
        secret_value: str,
    ):
        """
        发送秘密给请求的设备

        Args:
            target_user: 目标用户 ID
            target_device: 目标设备 ID
            request_id: 原始请求 ID
            secret_name: 秘密名称
            secret_value: Base64 编码的秘密值
        """
        try:
            # 构造 m.secret.send 内容
            content = {
                "request_id": request_id,
                "secret": secret_value,
            }

            # 需要加密发送
            # 首先获取目标设备的密钥
            await self._ensure_device_keys(target_user, [target_device])

            # 加密内容
            encrypted_content = await self._encrypt_to_device(
                target_user=target_user,
                target_device=target_device,
                event_type=M_SECRET_SEND,
                content=content,
            )

            if encrypted_content:
                # 发送加密的 to-device 消息
                await self.client.send_to_device(
                    event_type=M_ROOM_ENCRYPTED,
                    messages={target_user: {target_device: encrypted_content}},
                )
                mark_succeeded = getattr(self, "_mark_olm_send_succeeded", None)
                if callable(mark_succeeded):
                    mark_succeeded(target_user, target_device)
                logger.info(
                    "[E2EE-Secrets] 已发送秘密 "
                    f"{secret_name} 到设备 {self._mask_device_id(target_device)}"
                )
            else:
                logger.error(
                    "[E2EE-Secrets] 无法加密秘密消息到设备 "
                    f"{self._mask_device_id(target_device)}"
                )

        except Exception as e:
            logger.error(f"[E2EE-Secrets] 发送秘密失败：{e}")

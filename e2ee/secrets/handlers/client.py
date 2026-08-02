"""Request supported secrets from the user's other devices."""

import uuid

from astrbot.api import logger

from ....constants import M_SECRET_REQUEST


class E2EEManagerSecretsClientMixin:
    """向其他设备发起秘密请求。"""

    async def request_secret_from_devices(self, secret_name: str) -> str | None:
        """
        向其他设备请求秘密

        Args:
            secret_name: 秘密名称

        Returns:
            请求 ID
        """
        request_id = str(uuid.uuid4())

        try:
            # 获取自己的其他设备
            own_devices = await self._get_own_devices()
            if not own_devices:
                logger.warning("[E2EE-Secrets] 没有其他设备可请求秘密")
                return None

            # 构造请求内容
            content = {
                "action": "request",
                "requesting_device_id": self.device_id,
                "request_id": request_id,
                "name": secret_name,
            }

            # 记录待处理请求
            self._add_pending_secret_request(request_id, secret_name)

            messages = {}
            for device_id in own_devices:
                if device_id != self.device_id:
                    messages[device_id] = content
            if messages:
                await self.client.send_to_device(
                    event_type=M_SECRET_REQUEST,
                    messages={self.user_id: messages},
                )
                logger.info(
                    f"[E2EE-Secrets] 已向 {len(messages)} 个设备请求秘密 {secret_name}"
                )
                return request_id

            else:
                logger.warning("[E2EE-Secrets] 没有其他设备可请求")
                return None

        except Exception as e:
            logger.error(f"[E2EE-Secrets] 请求秘密失败：{e}")
            return None

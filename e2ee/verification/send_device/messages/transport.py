"""To-device transport for verification messages."""

import secrets

from astrbot.api import logger


class SASVerificationSendDeviceTransportMixin:
    async def _send_to_device(
        self, event_type: str, to_user: str, to_device: str, content: dict
    ):
        """发送 to_device 消息"""
        try:
            txn_id = secrets.token_hex(16)
            messages = {to_user: {to_device: content}}
            await self.client.send_to_device(event_type, messages, txn_id)
        except Exception as e:
            logger.error(f"[E2EE-Verify] 发送 {event_type} 失败：{e}")

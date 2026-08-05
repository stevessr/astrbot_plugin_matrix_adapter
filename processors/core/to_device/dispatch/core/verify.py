"""Verification and secret-request to-device handlers."""

from astrbot.api import logger


async def _handle_verification_to_device(
    self, event_type: str, sender: str, content: dict
) -> None:
    if self.e2ee_manager:
        try:
            await self.e2ee_manager.handle_verification_event(
                event_type, sender, content
            )
        except Exception as e:
            logger.error(f"处理验证事件失败：{e}")
    else:
        logger.debug(f"E2EE 未启用，忽略验证事件：{event_type}")


async def _handle_secret_request(self, sender: str, content: dict) -> None:
    if self.e2ee_manager:
        try:
            # 获取发送设备 ID
            sender_device = content.get("requesting_device_id", "")
            await self.e2ee_manager.handle_secret_request(
                sender=sender,
                content=content,
                sender_device=sender_device,
            )
        except Exception as e:
            logger.error(f"处理 m.secret.request 事件失败：{e}")

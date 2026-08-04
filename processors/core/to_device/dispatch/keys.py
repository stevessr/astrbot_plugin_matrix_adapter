"""To-device room-key request and withheld event handling."""

from astrbot.api import logger

from .....constants import MEGOLM_ALGO


class MatrixEventProcessorToDeviceKeysMixin:
    """Handle room-key requests and withheld notices."""

    async def _handle_room_key_withheld(self, sender: str, content: dict) -> None:
        if self.e2ee_manager:
            try:
                await self.e2ee_manager.handle_room_key_withheld(
                    sender,
                    content,
                )
            except Exception as e:
                logger.error(f"Failed to process m.room_key.withheld: {e}")

    async def _handle_room_key_request(
        self,
        sender: str,
        content: dict,
        cancelled_requests: set[tuple[str, str, str]],
    ) -> None:
        if not self.e2ee_manager:
            return
        try:
            action = content.get("action", "")
            requesting_device_id = content.get("requesting_device_id", "")
            request_id = content.get("request_id", "")
            body = content.get("body", {})

            if action == "request":
                # 跳过自己设备发出的请求
                if (
                    self.e2ee_manager
                    and requesting_device_id == self.e2ee_manager.device_id
                ):
                    logger.debug("忽略来自自己设备的密钥请求")
                    return

                if (
                    not isinstance(request_id, str)
                    or not request_id
                    or not isinstance(body, dict)
                    or (
                        sender,
                        requesting_device_id,
                        request_id,
                    )
                    in cancelled_requests
                ):
                    logger.debug(
                        "Ignoring cancelled room-key request or one "
                        "without a request_id"
                    )
                    return

                room_id = body.get("room_id", "")
                session_id = body.get("session_id", "")

                if body.get("algorithm") != MEGOLM_ALGO or not all(
                    isinstance(value, str) and value
                    for value in (
                        requesting_device_id,
                        room_id,
                        session_id,
                    )
                ):
                    logger.warning(
                        "Ignoring malformed room-key request: "
                        f"device={requesting_device_id or '<empty>'} "
                        f"room={room_id or '<empty>'} "
                        f"session={session_id or '<empty>'}"
                    )
                    return

                logger.debug(
                    f"收到密钥请求：来自设备 {requesting_device_id}，"
                    f"room={(room_id or '')[:16]}..., session={(session_id or '')[:8]}..."
                )

                # 调用 E2EE 管理器响应密钥请求
                await self.e2ee_manager.respond_to_key_request(
                    sender=sender,
                    requesting_device_id=requesting_device_id,
                    room_id=room_id,
                    session_id=session_id,
                )
            elif action == "request_cancellation":
                if not all(
                    isinstance(value, str) and value
                    for value in (request_id, requesting_device_id)
                ):
                    logger.warning("Ignoring malformed room-key request cancellation")
                    return
                logger.debug(f"密钥请求已取消：device={requesting_device_id}")
        except Exception as e:
            logger.error(f"处理 m.room_key_request 事件失败：{e}")

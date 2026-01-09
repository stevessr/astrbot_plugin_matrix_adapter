"""
Matrix adapter message helpers.
"""

from astrbot.api import logger

from .constants import DEFAULT_TYPING_TIMEOUT_MS


class MatrixAdapterMessageMixin:
    async def message_callback(self, room, event):
        """
        Process a message event (called by event processor after filtering)

        Args:
            room: Room object
            event: Parsed event object
        """
        try:
            if getattr(event, "msgtype", None):
                try:
                    await self.client.set_typing(
                        room.room_id, typing=True, timeout=DEFAULT_TYPING_TIMEOUT_MS
                    )
                except Exception as e:
                    logger.debug(f"发送输入通知失败：{e}")
                abm = await self.receiver.convert_message(room, event)
            else:
                abm = await self.receiver.convert_system_event(room, event)
            if abm is None:
                logger.warning(f"转换消息失败：{event}")
                return
            await self.handle_msg(abm)
        except Exception as e:
            logger.error(f"消息回调时出错：{e}")

    async def handle_msg(self, message):
        try:
            from .matrix_event import MatrixPlatformEvent

            message_event = MatrixPlatformEvent(
                message_str=message.message_str,
                message_obj=message,
                platform_meta=self.meta(),
                session_id=message.session_id,
                client=self.client,
                enable_threading=self._matrix_config.enable_threading,
                e2ee_manager=self.e2ee_manager,
                use_notice=self._matrix_config.use_notice,
            )
            self.commit_event(message_event)
            logger.debug(
                f"Message event committed: session={getattr(message, 'session_id', 'N/A')}, type={getattr(message, 'type', 'N/A')}, sender={getattr(message.sender, 'user_id', 'N/A') if hasattr(message, 'sender') else 'N/A'}"
            )
        except Exception as e:
            logger.error(f"处理消息失败：{e}")

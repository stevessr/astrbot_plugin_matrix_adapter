"""Adapter event dispatch operations."""

from astrbot.api import logger

from .common import _get_plugin_config


class MatrixAdapterMessageDispatchMixin:
    """Commit converted messages into Matrix platform events."""

    async def handle_msg(
        self,
        message,
        event_id: str | None = None,
        room_live_messaging_enabled: bool | None = None,
    ):
        try:
            from ....events.matrix import MatrixPlatformEvent

            message_event = MatrixPlatformEvent(
                message_str=message.message_str,
                message_obj=message,
                platform_meta=self.meta(),
                session_id=message.session_id,
                client=self.client,
                enable_threading=self._matrix_config.enable_threading,
                room_live_messaging_enabled=room_live_messaging_enabled,
                live_message_update_interval_ms=getattr(
                    self._matrix_config,
                    "live_message_update_interval_ms",
                    2000,
                ),
                e2ee_manager=self.e2ee_manager,
                use_notice=self._matrix_config.use_notice,
                adaptive_thread_reply=_get_plugin_config().adaptive_thread_reply,
                send_typing=_get_plugin_config().send_typing,
            )

            self.commit_event(message_event)
            # 仅记录必要的事件元信息，避免在 debug 中打印过多用户标识
            logger.debug(
                f"Message event committed: session={getattr(message, 'session_id', 'N/A')}, type={getattr(message, 'type', 'N/A')}"
            )
        except Exception as e:
            logger.error(f"处理消息失败：{e}")

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

            # 保存消息历史到 PlatformMessageHistory
            if self.message_history_manager and abm:
                try:
                    # 构建消息内容
                    content = {
                        "message": [],
                        "raw_message": abm.message_str,
                    }

                    # 转换消息链为可序列化格式
                    from astrbot.api.message_components import (
                        At,
                        AtAll,
                        Image,
                        Plain,
                        Reply,
                    )

                    for component in abm.message:
                        if isinstance(component, Plain):
                            content["message"].append(
                                {"type": "plain", "text": component.text}
                            )
                        elif isinstance(component, Image):
                            content["message"].append(
                                {
                                    "type": "image",
                                    "path": getattr(component, "path", ""),
                                }
                            )
                        elif isinstance(component, At):
                            content["message"].append(
                                {
                                    "type": "at",
                                    "qq": component.qq,
                                    "name": component.name,
                                }
                            )
                        elif isinstance(component, AtAll):
                            content["message"].append({"type": "at_all"})
                        elif isinstance(component, Reply):
                            content["message"].append(
                                {
                                    "type": "reply",
                                    "id": component.id,
                                    "message_str": component.message_str,
                                    "sender_id": component.sender_id,
                                    "sender_nickname": component.sender_nickname,
                                }
                            )
                        else:
                            # 其他类型组件
                            content["message"].append(
                                {
                                    "type": getattr(component, "type", "unknown"),
                                    "data": getattr(component, "data", {}),
                                }
                            )

                    # 获取发送者信息
                    sender_id = (
                        abm.sender.user_id
                        if hasattr(abm, "sender") and abm.sender
                        else ""
                    )
                    sender_name = (
                        abm.sender.nickname
                        if hasattr(abm, "sender") and abm.sender
                        else ""
                    )

                    # 保存到数据库
                    await self.message_history_manager.insert(
                        platform_id=self.meta().id or "matrix",
                        user_id=abm.session_id,
                        content=content,
                        sender_id=sender_id,
                        sender_name=sender_name,
                    )
                    logger.debug(
                        f"已保存消息历史：session_id={abm.session_id}, sender={sender_name}"
                    )
                except Exception as e:
                    logger.warning(f"保存消息历史失败：{e}")

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

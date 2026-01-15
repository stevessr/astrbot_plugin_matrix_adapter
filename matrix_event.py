from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, MessageChain
from astrbot.api.platform import AstrBotMessage, PlatformMetadata

# 导入 Sticker 组件
from .matrix_event_send import send_with_client_impl
from .matrix_event_streaming import send_streaming_impl


class MatrixPlatformEvent(AstrMessageEvent):
    """Matrix 平台事件处理器（不依赖 matrix-nio）"""

    def __init__(
        self,
        message_str: str,
        message_obj: AstrBotMessage,
        platform_meta: PlatformMetadata,
        session_id: str,
        client,
        enable_threading: bool = False,
        e2ee_manager=None,
        use_notice: bool = False,
    ):
        super().__init__(message_str, message_obj, platform_meta, session_id)
        self.client = client  # MatrixHTTPClient instance
        self.enable_threading = enable_threading  # 试验性：是否默认开启嘟文串模式
        self.e2ee_manager = e2ee_manager
        self.use_notice = use_notice  # 使用 m.notice 而不是 m.text

    @staticmethod
    async def send_with_client(
        client,
        message_chain: MessageChain,
        room_id: str,
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
        original_message_info: dict | None = None,
        e2ee_manager=None,
        max_upload_size: int | None = None,
        use_notice: bool = False,
    ) -> int:
        """使用提供的 client 将指定消息链发送到指定房间。"""
        return await send_with_client_impl(
            client=client,
            message_chain=message_chain,
            room_id=room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            original_message_info=original_message_info,
            e2ee_manager=e2ee_manager,
            max_upload_size=max_upload_size,
            use_notice=use_notice,
        )

    async def send(self, message_chain: MessageChain):
        """发送消息"""
        self.message_chain = message_chain
        # Matrix 的 room_id 即为会话 ID
        room_id = self.session_id

        if message_chain.type in {"tool_call", "tool_direct_result"}:
            try:
                from astrbot.api.message_components import Reply as _Reply

                has_reply = any(
                    isinstance(seg, _Reply) for seg in message_chain.chain or []
                )
                reply_id = getattr(self.message_obj, "message_id", None)
                sender_id = getattr(
                    getattr(self.message_obj, "sender", None),
                    "user_id",
                    None,
                )
                if not has_reply and reply_id:
                    message_chain.chain.insert(
                        0,
                        _Reply(id=reply_id, sender_id=sender_id),
                    )
            except Exception:
                pass

        # 检查是否需要使用嘟文串模式
        reply_to = None
        thread_root = None
        use_thread = False

        # 尝试从消息链中提取 Reply 段
        try:
            from astrbot.api.message_components import Reply as _Reply

            for seg in message_chain.chain:
                if isinstance(seg, _Reply) and getattr(seg, "id", None):
                    reply_to = str(seg.id)
                    break
        except Exception:
            pass

        # 如果没有找到回复对象，但消息链中包含 Reply 组件（表示开启了回复模式）
        # 则尝试获取自己最近发送的消息作为回复对象
        if not reply_to:
            try:
                from astrbot.api.message_components import Reply as _Reply

                has_reply_component = any(
                    isinstance(seg, _Reply) for seg in message_chain.chain
                )

                if has_reply_component:
                    # 获取房间当前状态以找到自己的用户 ID
                    try:
                        # 尝试通过客户端获取自己的用户 ID
                        whoami = await self.client.whoami()
                        my_user_id = whoami.get("user_id")

                        if my_user_id:
                            # 获取房间最近的消息
                            messages_resp = await self.client.room_messages(
                                room_id=room_id,
                                direction="b",  # 向后获取（最新的消息）
                                limit=50,  # 获取最近 50 条消息
                            )

                            # 查找自己最近发送的消息
                            chunk = messages_resp.get("chunk", [])
                            for event in chunk:
                                if (
                                    event.get("type") == "m.room.message"
                                    and event.get("sender") == my_user_id
                                    and event.get("content", {}).get("msgtype")
                                    in ("m.text", "m.notice")
                                ):
                                    reply_to = event.get("event_id")
                                    logger.debug(
                                        f"找到自己最近的消息作为回复对象：{reply_to}"
                                    )
                                    break
                    except Exception as e:
                        logger.debug(f"获取自己最近消息失败：{e}")
            except Exception as e:
                logger.debug(f"处理回复模式时出错：{e}")

        # 如果有回复，检查是否需要使用嘟文串模式
        original_message_info = None
        if reply_to:
            try:
                # 获取被回复消息的事件信息
                resp = await self.client.get_event(room_id, reply_to)
                if resp:
                    # 提取原始消息信息用于 fallback
                    original_message_info = {
                        "sender": resp.get("sender", ""),
                        "body": resp.get("content", {}).get("body", ""),
                    }

                    # 检查被回复消息是否已经是嘟文串的一部分
                    if "content" in resp:
                        relates_to = resp["content"].get("m.relates_to", {})
                        if relates_to.get("rel_type") == "m.thread":
                            # 如果是嘟文串的一部分，获取根消息 ID
                            thread_root = relates_to.get("event_id")
                            use_thread = True
                        elif self.enable_threading:
                            # 试验性功能：如果启用嘟文串模式，创建新的嘟文串
                            use_thread = True
                            thread_root = reply_to  # 将被回复的消息作为嘟文串根
                        else:
                            # 如果不是嘟文串，不要强制开启嘟文串模式，使用标准回复
                            use_thread = False
                            thread_root = None
            except Exception as e:
                logger.warning(f"Failed to get event for threading: {e}")

        await MatrixPlatformEvent.send_with_client(
            self.client,
            message_chain,
            room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            original_message_info=original_message_info,
            e2ee_manager=self.e2ee_manager,
            use_notice=self.use_notice,
        )

        return await super().send(message_chain)

    async def send_streaming(self, generator, use_fallback: bool = False):
        """Matrix 流式发送 - 使用消息编辑实现实时流式更新

        通过先发送初始消息，然后不断编辑该消息来实现流式输出效果。
        类似于 Telegram/Discord 机器人的实时打字效果。
        """
        await send_streaming_impl(self, generator, use_fallback)
        return await super().send_streaming(generator, use_fallback)

    async def react(self, emoji: str):
        """对消息添加表情回应。"""
        try:
            event_id = getattr(self.message_obj, "message_id", None)
            if not event_id and hasattr(self.message_obj, "raw_message"):
                event_id = getattr(self.message_obj.raw_message, "event_id", None)
            if not event_id:
                logger.warning("无法添加反应：缺少 event_id")
                return
            await self.client.send_reaction(self.session_id, event_id, emoji)
        except Exception as e:
            logger.error(f"发送表情反应失败：{e}")

    async def delete(self, reason: str | None = None, event_id: str | None = None):
        """删除（撤回）消息。"""
        try:
            target_event_id = event_id or getattr(self.message_obj, "message_id", None)
            if not target_event_id and hasattr(self.message_obj, "raw_message"):
                target_event_id = getattr(self.message_obj.raw_message, "event_id", None)
            if not target_event_id:
                logger.warning("无法删除消息：缺少 event_id")
                return
            await self.client.redact_event(
                self.session_id, str(target_event_id), reason=reason
            )
        except Exception as e:
            logger.error(f"删除消息失败：{e}")

"""Matrix platform event message orchestration."""

from astrbot.api.event import MessageChain


class MatrixPlatformEventSendCoreMixin:
    """Send message chains and resolve Matrix thread/reply context."""

    async def send(self, message_chain: MessageChain):
        """发送消息"""
        self.message_chain = message_chain
        # Matrix 的 room_id 即为会话 ID
        room_id = self.session_id

        is_fc_boundary = self._prepare_fc_boundary(message_chain)

        # 检查是否需要使用嘟文串模式
        reply_to = None
        thread_root = None
        use_thread = False
        reused_thread_context = False
        original_message_info = None
        has_reply_component = False
        thread_is_falling_back = False

        # 尝试从消息链中提取 Reply 段
        reply_to, has_reply_component = self._extract_reply_target(message_chain)

        # 分段回复的后续消息没有 Reply 组件。优先复用本次事件前一段已经
        # 解析好的线程上下文；如果没有上下文且启用了线程，则使用本次入站
        # 事件作为回复目标，使"关闭引用 + 开启消息串"仍能创建线程。
        if not reply_to:
            context = self._response_thread_context
            if isinstance(context, dict) and context.get("use_thread"):
                reply_to = context.get("reply_to")
                thread_root = context.get("thread_root")
                use_thread = bool(thread_root)
                original_message_info = context.get("original_message_info")
                thread_is_falling_back = bool(
                    context.get("thread_is_falling_back", False)
                )
                reused_thread_context = use_thread

        # 如果没有找到回复对象，但消息链中包含 Reply 组件（表示开启了回复模式）
        # 则尝试获取自己最近发送的消息作为回复对象
        if not reply_to:
            reply_to = await self._find_reply_fallback(room_id, has_reply_component)

        # 回复自适应：入站（唤醒）消息位于消息列内时，本次回复必须留在同一
        # 消息列，而不是回落到房间时间线。
        inbound_thread_root = (
            self._inbound_thread_root() if self.adaptive_thread_reply else None
        )

        # 没有 Reply 组件时（例如关闭 AstrBot 全局引用）直接使用入站事件
        # 作为线程目标。放在上面的兼容查询之后，保留空 Reply 组件原有的
        # "尝试回复最近一条 bot 消息"行为。
        if not reply_to and (self.enable_threading or inbound_thread_root):
            source_event_id = self._inbound_event_id()
            if source_event_id:
                reply_to = source_event_id
                # Keep the target for thread continuity without rendering it
                # as an explicit reply when AstrBot quote mode is disabled.
                thread_is_falling_back = True

        # 如果有回复，检查是否需要使用嘟文串模式
        if reply_to and not reused_thread_context:
            (
                thread_root,
                use_thread,
                original_message_info,
            ) = await self._resolve_thread_target(room_id, reply_to)

        # 回复自适应最终裁定：入站消息在消息列内时，锁定该消息列作为线程根，
        # 覆盖上面按回复目标推导出的结果（包括查询失败或目标不在消息列内）。
        if inbound_thread_root and reply_to and not reused_thread_context:
            inbound_event_id = self._inbound_event_id()
            if (
                inbound_event_id
                and reply_to != inbound_event_id
                and thread_root != inbound_thread_root
            ):
                # 回复目标位于本消息列之外，Matrix 不允许跨消息列引用，
                # 因此把引用目标退回到入站消息本身。
                reply_to = inbound_event_id
                thread_is_falling_back = True
            thread_root = inbound_thread_root
            use_thread = True

        # 发送前记住线程上下文。第一段可能带 Reply，后续分段没有 Reply，
        # 但每一段仍必须携带 m.thread 关系。只缓存真正的线程关系，普通
        # m.in_reply_to 回复保持 AstrBot 原本的行为。
        if use_thread and thread_root:
            self._response_thread_context = {
                "reply_to": reply_to or thread_root,
                "thread_root": thread_root,
                "use_thread": True,
                "original_message_info": original_message_info,
                "thread_is_falling_back": thread_is_falling_back,
            }
        elif reply_to and not reused_thread_context:
            # 当前调用明确指定了普通回复时，不要把上一次线程上下文泄漏
            # 到一个新的、非线程回复中。
            self._response_thread_context = None

        await self.send_with_client(
            self.client,
            message_chain,
            room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            original_message_info=original_message_info,
            e2ee_manager=self.e2ee_manager,
            use_notice=self.use_notice,
            thread_is_falling_back=thread_is_falling_back,
        )

        # FC 边界：清除线程上下文，后续回复另开新消息而非接续
        if is_fc_boundary:
            self._response_thread_context = None

        return await super().send(message_chain)

"""Matrix platform event message orchestration."""

from astrbot.api.event import MessageChain

from .adapt import MatrixPlatformEventSendAdaptMixin
from .resolve import MatrixPlatformEventSendResolveMixin
from .reuse import MatrixPlatformEventSendReuseMixin
from .store import MatrixPlatformEventSendStoreMixin


class MatrixPlatformEventSendCoreOrchestratorMixin(
    MatrixPlatformEventSendAdaptMixin,
    MatrixPlatformEventSendResolveMixin,
    MatrixPlatformEventSendReuseMixin,
    MatrixPlatformEventSendStoreMixin,
):
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

        (
            reply_to,
            thread_root,
            use_thread,
            reused_thread_context,
            original_message_info,
            thread_is_falling_back,
        ) = self._reuse_thread_context(reply_to)

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

        (
            thread_root,
            use_thread,
            original_message_info,
        ) = await self._resolve_thread_target_if_needed(
            room_id,
            reply_to,
            thread_root,
            use_thread,
            original_message_info,
            reused_thread_context,
        )

        (
            reply_to,
            thread_root,
            use_thread,
            thread_is_falling_back,
        ) = self._adjudicate_adaptive_reply(
            reply_to,
            thread_root,
            use_thread,
            reused_thread_context,
            inbound_thread_root,
            thread_is_falling_back,
        )

        self._persist_response_context(
            reply_to,
            thread_root,
            use_thread,
            original_message_info,
            thread_is_falling_back,
            reused_thread_context,
        )

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


__all__ = ["MatrixPlatformEventSendCoreOrchestratorMixin"]

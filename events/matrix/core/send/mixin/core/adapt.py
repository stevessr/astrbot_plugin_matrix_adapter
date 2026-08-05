"""Adaptive in-thread reply adjudication."""


class MatrixPlatformEventSendAdaptMixin:
    """Lock replies to the inbound message column when threading adaptively."""

    def _adjudicate_adaptive_reply(
        self,
        reply_to,
        thread_root,
        use_thread,
        reused_thread_context,
        inbound_thread_root,
        thread_is_falling_back,
    ):
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
        return reply_to, thread_root, use_thread, thread_is_falling_back


__all__ = ["MatrixPlatformEventSendAdaptMixin"]

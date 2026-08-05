"""Thread-context reuse for segmented replies."""


class MatrixPlatformEventSendReuseMixin:
    """Reuse the previously resolved thread context for follow-up segments."""

    def _reuse_thread_context(self, reply_to):
        if not reply_to:
            # 分段回复的后续消息没有 Reply 组件。优先复用本次事件前一段已经
            # 解析好的线程上下文；如果没有上下文且启用了线程，则使用本次入站
            # 事件作为回复目标，使"关闭引用 + 开启消息串"仍能创建线程。
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
                return (
                    reply_to,
                    thread_root,
                    use_thread,
                    reused_thread_context,
                    original_message_info,
                    thread_is_falling_back,
                )
        return reply_to, None, False, False, None, False


__all__ = ["MatrixPlatformEventSendReuseMixin"]

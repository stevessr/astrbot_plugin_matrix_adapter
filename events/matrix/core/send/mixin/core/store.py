"""Response thread-context persistence."""


class MatrixPlatformEventSendStoreMixin:
    """Remember thread context across segmented sends."""

    def _persist_response_context(
        self,
        reply_to,
        thread_root,
        use_thread,
        original_message_info,
        thread_is_falling_back,
        reused_thread_context,
    ):
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


__all__ = ["MatrixPlatformEventSendStoreMixin"]

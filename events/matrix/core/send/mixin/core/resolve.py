"""Thread-target resolution for non-reused replies."""


class MatrixPlatformEventSendResolveMixin:
    """Resolve the Matrix thread target for a reply."""

    async def _resolve_thread_target_if_needed(
        self,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        original_message_info,
        reused_thread_context,
    ):
        # 如果有回复，检查是否需要使用嘟文串模式
        if reply_to and not reused_thread_context:
            (
                thread_root,
                use_thread,
                original_message_info,
            ) = await self._resolve_thread_target(room_id, reply_to)
        return thread_root, use_thread, original_message_info


__all__ = ["MatrixPlatformEventSendResolveMixin"]

"""Thread relation helpers for Matrix streaming messages."""

from ... import core as _matrix_event_module


class MatrixPlatformEventMessagesRelationsMixin:
    """Build relations and resolve the current Matrix event module."""

    @staticmethod
    def _stream_event_module():
        """Return the current event module even after test/app reloads."""

        import sys

        package_name = __package__.rsplit(".", 2)[0]
        package = sys.modules.get(package_name)
        return getattr(package, "core", None) or _matrix_event_module

    def _build_stream_thread_relation(self) -> dict | None:
        """Build the initial message relation for a streamed thread reply.

        Replacement events point at the initial live event with ``m.replace``;
        Matrix keeps the initial event's thread relation when applying edits.
        """

        source_event_id = self._inbound_event_id()
        if not source_event_id:
            return None

        thread_root = self._inbound_thread_root()
        if thread_root:
            # 回复自适应：入站消息已在消息列内，流式回复必须留在同一消息列。
            if not (self.adaptive_thread_reply or self.enable_threading):
                return None
        else:
            # 入站消息不在消息列内，只有显式开启线程回复才新建消息列。
            if not self.enable_threading:
                return None
            thread_root = source_event_id

        return {
            "rel_type": "m.thread",
            "event_id": thread_root,
            "is_falling_back": True,
            "m.in_reply_to": {"event_id": source_event_id},
        }

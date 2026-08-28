"""Matrix platform event state and inbound relation helpers."""

from astrbot.api.platform import AstrBotMessage, PlatformMetadata

from ....utils.utils import resolve_matrix_room_id


class MatrixPlatformEventStateMixin:
    """Initialize event state and expose inbound event relation metadata."""

    def __init__(
        self,
        message_str: str,
        message_obj: AstrBotMessage,
        platform_meta: PlatformMetadata,
        session_id: str,
        client,
        enable_threading: bool = False,
        room_live_messaging_enabled: bool | None = None,
        live_message_update_interval_ms: int = 2000,
        e2ee_manager=None,
        use_notice: bool = False,
        adaptive_thread_reply: bool = True,
        send_typing: bool = False,
    ):
        super().__init__(message_str, message_obj, platform_meta, session_id)
        # AstrBot may replace ``self.session_id`` with a sender-scoped ID
        # after this event enters the pipeline when ``unique_session`` is
        # enabled.  Keep the Matrix transport target independent from that
        # logical session ID.  ``group_id``/message ``session_id`` are still
        # the native Matrix room ID at this point; the fallback also handles
        # events created from an already-isolated session.
        matrix_room_id = (
            getattr(message_obj, "group_id", None)
            or getattr(message_obj, "session_id", None)
            or session_id
        )
        self._matrix_room_id = resolve_matrix_room_id(matrix_room_id)
        self.client = client  # MatrixHTTPClient instance
        self.enable_threading = enable_threading  # 试验性：是否默认开启嘟文串模式
        # 回复自适应：入站（唤醒）消息位于消息列内时，回复也留在同一消息列。
        # 只跟随已存在的消息列，不会替 enable_threading 新建消息列。
        self.adaptive_thread_reply = adaptive_thread_reply
        # 流式是独立发送接口，无需额外总开关。仅当房间通过
        # MSC4357 状态明确声明 ``enabled: false`` 时退化为普通回复。
        self.live_messages_allowed = room_live_messaging_enabled is not False
        try:
            update_interval_ms = int(live_message_update_interval_ms)
        except (TypeError, ValueError):
            update_interval_ms = 2000
        self.live_message_update_interval_ms = min(
            10000,
            max(1000, update_interval_ms),
        )
        self.e2ee_manager = e2ee_manager
        self.use_notice = use_notice  # 使用 m.notice 而不是 m.text
        # 是否向房间发送「正在输入」状态（插件级开关，默认关闭）。
        # 不能命名为 ``send_typing``：AstrBot 4.26+ 会调用同名的异步
        # 生命周期方法，实例布尔属性会将方法遮蔽成不可调用对象。
        self._send_typing_enabled = bool(send_typing)

        # AstrBot 的分段回复会把 Reply/At 头部组件只放在第一段，之后的
        # ``event.send`` 调用只带 Plain（见 RespondStage）。Matrix 的线程关系
        # 是每条事件独立声明的，因此不能仅依赖当前消息段里的 Reply 组件。
        # 这里保存本次入站事件发送过程中解析出的线程上下文，让后续分段
        # 继续使用同一个线程根，而不会回落到房间时间线。
        self._response_thread_context: dict | None = None

        # 正常情况不覆盖 AstrBot 的流式调度；平台已声明支持
        # send_streaming，只在房间明确禁用时阻止上游产生流。
        if not self.live_messages_allowed:
            self.set_extra("enable_streaming", False)

    @property
    def matrix_room_id(self) -> str:
        """Return the native Matrix room ID, not AstrBot's logical session."""

        return getattr(self, "_matrix_room_id", "") or resolve_matrix_room_id(
            getattr(self, "session_id", "")
        )

    def _inbound_event_id(self) -> str | None:
        """本次入站（唤醒）事件的 ``event_id``。"""

        source_event_id = getattr(self.message_obj, "message_id", None)
        if not source_event_id:
            raw_message = getattr(self.message_obj, "raw_message", None)
            if isinstance(raw_message, dict):
                source_event_id = raw_message.get("event_id")
            else:
                source_event_id = getattr(raw_message, "event_id", None)
        return str(source_event_id) if source_event_id else None

    def _inbound_thread_root(self) -> str | None:
        """入站事件所在消息列的根事件；不在消息列内时返回 ``None``。"""

        raw_message = getattr(self.message_obj, "raw_message", None)
        if isinstance(raw_message, dict):
            content = raw_message.get("content", {})
        else:
            content = getattr(raw_message, "content", {})
        if not isinstance(content, dict):
            return None
        relation = content.get("m.relates_to")
        if not isinstance(relation, dict):
            return None
        if relation.get("rel_type") != "m.thread":
            return None
        thread_root = relation.get("event_id")
        return str(thread_root) if thread_root else None

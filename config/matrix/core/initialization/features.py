"""Matrix sync, threading, message, and call-event configuration state."""

from .....constants import DEFAULT_TIMEOUT_MS_30000


class MatrixConfigFeaturesInitializationMixin:
    """Initialize sync, threading, message, and call feature fields."""

    def _initialize_feature_state(self) -> None:
        self.auto_join_rooms = self._parse_bool(
            self.config.get("matrix_auto_join_rooms"),
            True,
        )
        self.sync_timeout = self._parse_int(
            self.config.get("matrix_sync_timeout"),
            DEFAULT_TIMEOUT_MS_30000,
            minimum=1000,
        )

        # 嘟文串（Threading）配置
        # 当启用时，回复消息会创建/加入线程而非普通的时间线回复
        # 这是一个试验性功能，可能不是所有 Matrix 客户端都支持
        self.enable_threading = self._parse_bool(
            self.config.get("matrix_enable_threading"),
            False,
        )

        # MSC4357 recommends coalescing updates at roughly a 2-3 second cadence
        # rather than emitting one replacement per token/keystroke. Keep the
        # interval configurable while enforcing a conservative lower bound.
        self.live_message_update_interval_ms = self._parse_int(
            self.config.get("matrix_live_message_update_interval_ms"),
            2000,
            minimum=1000,
            maximum=10000,
        )

        # 消息类型配置
        # 当启用时，机器人使用 m.notice 而不是 m.text 发送消息
        # m.notice 通常用于机器人消息，不会触发通知声音
        self.use_notice = self._parse_bool(
            self.config.get("matrix_use_notice"),
            False,
        )

        # Live 通话事件配置
        # 启用后，VoIP（1 对 1）/ MatrixRTC（群组 Live）通话事件会被归一化为
        # 系统提示消息呈现给上层，便于机器人感知通话发生与状态变化。
        # 机器人无法真正参与 WebRTC 媒体，因此这些事件不会触发 LLM 回复。
        self.enable_call_events = self._parse_bool(
            self.config.get("matrix_enable_call_events"),
            False,
        )
        # 呈现 1 对 1 VoIP 通话生命周期事件（发起/接听/挂断/拒绝/转移）
        self.call_include_1to1 = self._parse_bool(
            self.config.get("matrix_call_include_1to1"),
            True,
        )
        # 呈现 MatrixRTC 群组 / Live 通话事件（通话开始/结束、成员加入/离开）
        self.call_include_group = self._parse_bool(
            self.config.get("matrix_call_include_group"),
            True,
        )
        # 呈现来电响铃 / 通知事件（MSC4075）
        self.call_include_ringing = self._parse_bool(
            self.config.get("matrix_call_include_ringing"),
            True,
        )
        # 抑制高频底层信令事件（candidates/negotiate/select_answer 等）
        self.call_suppress_signalling = self._parse_bool(
            self.config.get("matrix_call_suppress_signalling"),
            True,
        )

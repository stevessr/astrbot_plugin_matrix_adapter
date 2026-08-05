"""
Matrix Live 通话（VoIP / MatrixRTC）事件适配的共享逻辑。

本模块刻意只依赖标准库，使其可以被 config / event_processor / receiver 等
任意模块安全导入（包括单元测试中通过 sys.modules 桩注入的环境）。

覆盖的事件族：

- 1 对 1 VoIP（MSC2746，现已进入正式规范的 ``m.call.*``）：
  invite / answer / hangup / reject / replaces 等生命周期事件，以及
  candidates / negotiate / select_answer / sdp_stream_metadata_changed /
  asserted_identity 等高频信令事件。
- MatrixRTC 群组 / Live 通话（MSC3401 / MSC4143）：
  ``m.call`` 群组通话状态事件，以及 ``m.call.member`` /
  ``org.matrix.msc3401.call.member`` / ``m.rtc.member`` 成员状态事件。
- 来电响铃通知（MSC4075）：``m.call.notify`` / ``org.matrix.msc4075.call.notify``。

机器人无法真正参与 WebRTC 媒体，因此「适配」的含义是：把这些事件归一化为
系统提示文本，让上层（AstrBot 工作流 / 存档）能够感知通话的发生与状态变化，
而不会触发 LLM 自动「接听」。
"""

from .media import _invite_media_kind
from .member import _member_has_left
from .text import format_call_event_text

__all__ = [
    "_invite_media_kind",
    "_member_has_left",
    "format_call_event_text",
]

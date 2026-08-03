"""Event families and configuration for Matrix calls."""

from dataclasses import dataclass

from ...constants import M_RTC_DECLINE, MSC4310_RTC_DECLINE

# --- 事件类型常量 -----------------------------------------------------------

# 1 对 1 通话生命周期事件（值得呈现给用户）
CALL_1TO1_LIFECYCLE_EVENT_TYPES = frozenset(
    {
        "m.call.invite",
        "m.call.answer",
        "m.call.hangup",
        "m.call.reject",
        "m.call.replaces",
    }
)

# 高频 / 底层信令事件（默认抑制，避免刷屏）
CALL_SIGNALLING_EVENT_TYPES = frozenset(
    {
        "m.call.candidates",
        "m.call.negotiate",
        "m.call.select_answer",
        "m.call.sdp_stream_metadata_changed",
        "m.call.asserted_identity",
        "org.matrix.call.asserted_identity",
    }
)

# MatrixRTC 群组通话对象状态事件（state event，state_key 为 call id）
CALL_GROUP_OBJECT_EVENT_TYPES = frozenset({"m.call"})

# MatrixRTC 成员状态事件（state event）
CALL_GROUP_MEMBER_EVENT_TYPES = frozenset(
    {
        "m.call.member",
        "org.matrix.msc3401.call.member",
        "m.rtc.member",
    }
)

# 来电响铃 / 通知事件（MSC4075）
CALL_NOTIFY_EVENT_TYPES = frozenset(
    {
        "m.call.notify",
        "org.matrix.msc4075.call.notify",
    }
)

# 通话拒接事件（MSC4310）：以 m.reference 关联 m.rtc.notification
CALL_DECLINE_EVENT_TYPES = frozenset({M_RTC_DECLINE, MSC4310_RTC_DECLINE})

# 事件类别标识
CATEGORY_1TO1 = "1to1"
CATEGORY_GROUP_OBJECT = "group_object"
CATEGORY_GROUP_MEMBER = "group_member"
CATEGORY_RINGING = "ringing"
CATEGORY_DECLINE = "decline"
CATEGORY_SIGNALLING = "signalling"


# --- 配置对象 ---------------------------------------------------------------


@dataclass(frozen=True)
class CallEventConfig:
    """Live 通话事件呈现配置（per-adapter）。"""

    enabled: bool = False
    include_1to1: bool = True
    include_group: bool = True
    include_ringing: bool = True
    suppress_signalling: bool = True


# 默认配置：未启用，等价于历史行为（直接忽略 m.call.* 事件）。
DEFAULT_CALL_EVENT_CONFIG = CallEventConfig()

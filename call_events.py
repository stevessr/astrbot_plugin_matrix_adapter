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

from dataclasses import dataclass

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

# 事件类别标识
CATEGORY_1TO1 = "1to1"
CATEGORY_GROUP_OBJECT = "group_object"
CATEGORY_GROUP_MEMBER = "group_member"
CATEGORY_RINGING = "ringing"
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


# --- 分类与门控逻辑 ---------------------------------------------------------


def classify_call_event(event_type: object) -> str | None:
    """将事件类型映射到通话事件类别；非通话事件返回 None。"""
    if not isinstance(event_type, str) or not event_type:
        return None
    if event_type in CALL_NOTIFY_EVENT_TYPES:
        return CATEGORY_RINGING
    if event_type in CALL_GROUP_MEMBER_EVENT_TYPES:
        return CATEGORY_GROUP_MEMBER
    if event_type in CALL_GROUP_OBJECT_EVENT_TYPES:
        return CATEGORY_GROUP_OBJECT
    if event_type in CALL_1TO1_LIFECYCLE_EVENT_TYPES:
        return CATEGORY_1TO1
    if event_type in CALL_SIGNALLING_EVENT_TYPES:
        return CATEGORY_SIGNALLING
    # 兜底：未知的 m.call.* 子类型按信令处理（默认抑制）。
    if event_type.startswith("m.call."):
        return CATEGORY_SIGNALLING
    return None


def is_call_event_type(event_type: object) -> bool:
    """判断事件类型是否属于 VoIP / MatrixRTC 通话事件族。"""
    return classify_call_event(event_type) is not None


def should_surface_call_event(event_type: object, config: object) -> bool:
    """根据配置判断某通话事件是否应被呈现为系统消息。"""
    category = classify_call_event(event_type)
    if category is None:
        return False
    if not getattr(config, "enabled", False):
        return False
    if category == CATEGORY_1TO1:
        return bool(getattr(config, "include_1to1", True))
    if category in (CATEGORY_GROUP_OBJECT, CATEGORY_GROUP_MEMBER):
        return bool(getattr(config, "include_group", True))
    if category == CATEGORY_RINGING:
        return bool(getattr(config, "include_ringing", True))
    if category == CATEGORY_SIGNALLING:
        return not bool(getattr(config, "suppress_signalling", True))
    return False


# --- 文本格式化 -------------------------------------------------------------


def _invite_media_kind(content: dict) -> str:
    """从 invite 的 SDP offer 粗略判断是语音还是视频通话。"""
    offer = content.get("offer")
    sdp = ""
    if isinstance(offer, dict):
        sdp = str(offer.get("sdp") or "")
    if "m=video" in sdp:
        return "video"
    if "m=audio" in sdp:
        return "voice"
    return ""


def _member_has_left(content: dict) -> bool:
    """判断 MatrixRTC 成员状态事件表示「离开」还是「加入」通话。"""
    if not content:
        return True
    # MSC3401：memberships / m.calls 数组为空表示离开。
    for key in ("memberships", "m.calls"):
        value = content.get(key)
        if isinstance(value, list):
            return len(value) == 0
    # MSC4143 m.rtc.member：包含通话标识字段即视为加入，空字典即离开。
    for key in (
        "call_id",
        "application",
        "device_id",
        "focus_active",
        "foci_preferred",
        "scope",
    ):
        if key in content:
            return False
    return len(content) == 0


def format_call_event_text(event: object) -> str | None:
    """把通话事件归一化为 ``[Call] ...`` 系统提示文本；无法呈现时返回 None。"""
    event_type = getattr(event, "event_type", "") or ""
    category = classify_call_event(event_type)
    if category is None:
        return None

    content = getattr(event, "content", None)
    if not isinstance(content, dict):
        content = {}
    sender = str(getattr(event, "sender", "") or "") or "Someone"
    state_key = getattr(event, "state_key", None)

    if category == CATEGORY_1TO1:
        if event_type == "m.call.invite":
            kind = _invite_media_kind(content)
            if kind:
                return f"[Call] {sender} started a {kind} call"
            return f"[Call] {sender} started a call"
        if event_type == "m.call.answer":
            return f"[Call] {sender} answered the call"
        if event_type == "m.call.hangup":
            reason = content.get("reason")
            if reason and str(reason) not in {"user_hangup", "user"}:
                return f"[Call] {sender} ended the call (reason: {reason})"
            return f"[Call] {sender} ended the call"
        if event_type == "m.call.reject":
            return f"[Call] {sender} rejected the call"
        if event_type == "m.call.replaces":
            return f"[Call] {sender} transferred the call"
        return f"[Call] {sender} updated the call"

    if category == CATEGORY_GROUP_OBJECT:
        terminated = content.get("m.terminated") or content.get("terminated")
        if not content or terminated:
            return "[Call] the group call ended"
        call_type = content.get("m.type") or content.get("type")
        suffix = f" ({call_type})" if call_type else ""
        return f"[Call] {sender} started a group call{suffix}"

    if category == CATEGORY_GROUP_MEMBER:
        member = str(state_key or sender or "Someone")
        if _member_has_left(content):
            return f"[Call] {member} left the group call"
        return f"[Call] {member} joined the group call"

    if category == CATEGORY_RINGING:
        notify_type = content.get("notify_type") or content.get("m.notify_type")
        if notify_type == "ring":
            return f"[Call] {sender} is ringing for a call"
        return f"[Call] {sender} sent a call notification"

    if category == CATEGORY_SIGNALLING:
        label = event_type.rsplit(".", 1)[-1] or event_type
        return f"[Call] {sender} sent call signalling ({label})"

    return None

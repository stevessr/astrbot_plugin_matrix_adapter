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

from .classification import classify_call_event
from .constants import (
    CATEGORY_1TO1,
    CATEGORY_DECLINE,
    CATEGORY_GROUP_MEMBER,
    CATEGORY_GROUP_OBJECT,
    CATEGORY_RINGING,
    CATEGORY_SIGNALLING,
)

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

    if category == CATEGORY_DECLINE:
        relates_to = content.get("m.relates_to") if isinstance(content, dict) else None
        related = ""
        if isinstance(relates_to, dict) and relates_to.get("event_id"):
            related = f" (notification {relates_to.get('event_id')})"
        return f"[Call] {sender} declined the call{related}"

    if category == CATEGORY_SIGNALLING:
        label = event_type.rsplit(".", 1)[-1] or event_type
        return f"[Call] {sender} sent call signalling ({label})"

    return None

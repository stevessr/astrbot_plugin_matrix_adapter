"""Call event text formatting."""

from ..classification import classify_call_event
from ..constants import (
    CATEGORY_1TO1,
    CATEGORY_DECLINE,
    CATEGORY_GROUP_MEMBER,
    CATEGORY_GROUP_OBJECT,
    CATEGORY_RINGING,
    CATEGORY_SIGNALLING,
)
from .media import _invite_media_kind
from .member import _member_has_left


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

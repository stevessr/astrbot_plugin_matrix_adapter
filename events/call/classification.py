"""Classification and visibility gates for Matrix call events."""

from .constants import (
    CALL_1TO1_LIFECYCLE_EVENT_TYPES,
    CALL_DECLINE_EVENT_TYPES,
    CALL_GROUP_MEMBER_EVENT_TYPES,
    CALL_GROUP_OBJECT_EVENT_TYPES,
    CALL_NOTIFY_EVENT_TYPES,
    CALL_SIGNALLING_EVENT_TYPES,
    CATEGORY_1TO1,
    CATEGORY_DECLINE,
    CATEGORY_GROUP_MEMBER,
    CATEGORY_GROUP_OBJECT,
    CATEGORY_RINGING,
    CATEGORY_SIGNALLING,
)

# --- 分类与门控逻辑 ---------------------------------------------------------


def classify_call_event(event_type: object) -> str | None:
    """将事件类型映射到通话事件类别；非通话事件返回 None。"""
    if not isinstance(event_type, str) or not event_type:
        return None
    if event_type in CALL_NOTIFY_EVENT_TYPES:
        return CATEGORY_RINGING
    if event_type in CALL_DECLINE_EVENT_TYPES:
        return CATEGORY_DECLINE
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
    if category == CATEGORY_DECLINE:
        return bool(getattr(config, "include_ringing", True))
    if category == CATEGORY_SIGNALLING:
        return not bool(getattr(config, "suppress_signalling", True))
    return False

"""Shared formatting helpers for room-state event handlers."""


def _format_member(user_id: str | None, display_name: str | None = None) -> str:
    user = str(user_id or "").strip()
    name = str(display_name or "").strip()
    if name and user and name != user:
        return f"{name} ({user})"
    return name or user or "Unknown user"


def _format_optional_reason(reason: object) -> str:
    if not reason:
        return ""
    return f": {reason}"


def _get_prev_content(event) -> dict:
    unsigned = getattr(event, "unsigned", None) or {}
    if not isinstance(unsigned, dict):
        return {}
    prev_content = unsigned.get("prev_content") or {}
    return prev_content if isinstance(prev_content, dict) else {}


def _format_limited_list(values: object, *, limit: int = 5) -> str:
    if not isinstance(values, list):
        return ""
    normalized = [str(item) for item in values if str(item)]
    if not normalized:
        return ""
    text = ", ".join(normalized[:limit])
    if len(normalized) > limit:
        text += f" (+{len(normalized) - limit} more)"
    return text

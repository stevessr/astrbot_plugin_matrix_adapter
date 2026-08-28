"""Parsing and text helpers used by Matrix utilities."""


def parse_bool(value: object, default: bool = False) -> bool:
    """Consolidated boolean parsing helper."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on", "enable", "enabled"}:
        return True
    if normalized in {"0", "false", "no", "off", "disable", "disabled"}:
        return False
    return default


def resolve_matrix_room_id(session_id: object) -> str:
    """Resolve a Matrix room ID from a native or isolated AstrBot session.

    AstrBot's ``unique_session`` mode currently builds Matrix group session
    IDs as ``<sender_id>_<room_id>``.  Matrix room IDs start with ``!``; use
    that boundary instead of splitting on the last underscore so underscores
    in either the sender or room ID remain intact.
    """
    if not isinstance(session_id, str):
        return ""

    normalized = session_id.strip()
    if not normalized:
        return ""

    _, separator, room_id = normalized.partition("_!")
    return f"!{room_id}" if separator else normalized


def mask_device_id(device_id: str | None) -> str:
    """统一的 device_id 脱敏显示函数。"""
    if not isinstance(device_id, str) or not device_id:
        return "<empty>"
    normalized = device_id.strip()
    if len(normalized) <= 4:
        return "***"
    return f"{normalized[:2]}***{normalized[-2:]}"


def _extract_text_repr(value) -> str:
    """Extract a text representation from a Matrix event content value."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("body") or value.get("text") or "")
    if isinstance(value, list):
        for item in value:
            text = _extract_text_repr(item)
            if text:
                return text
    return ""


__all__ = [
    "parse_bool",
    "resolve_matrix_room_id",
    "mask_device_id",
    "_extract_text_repr",
]

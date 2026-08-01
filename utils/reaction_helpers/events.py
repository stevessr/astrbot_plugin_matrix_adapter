"""Matrix event text and timestamp extraction helpers."""

from typing import Any


def extract_matrix_event_text(event: dict[str, Any] | None) -> str:
    """Extract searchable plain text from a Matrix room event."""
    if not isinstance(event, dict):
        return ""
    content = event.get("content")
    if not isinstance(content, dict):
        content = {}

    body = str(content.get("body") or "").strip()
    if body:
        try:
            from ..utils import MatrixUtils

            body = MatrixUtils.strip_reply_fallback(body)
        except Exception:
            pass
        return str(body or "").strip()

    # Some non-text events only expose a description-like field.
    for key in ("filename", "name", "title"):
        value = str(content.get(key) or "").strip()
        if value:
            return value
    return ""


def event_origin_server_ts_ms(event: dict[str, Any] | None) -> int | None:
    """Read ``origin_server_ts`` (ms) from a Matrix event if present."""
    if not isinstance(event, dict):
        return None
    raw = event.get("origin_server_ts")
    if raw is None:
        raw = event.get("server_timestamp")
    if raw is None:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return value

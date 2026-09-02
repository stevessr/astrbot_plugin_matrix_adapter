"""Inbound ``m.replace`` message normalization."""

from typing import Any

from astrbot.api import logger

from .....constants import REL_TYPE_REPLACE


def _extract_content_text(content: Any) -> str:
    """Extract the short text representation used for an edit quote."""
    if not isinstance(content, dict):
        return ""

    new_content = content.get("m.new_content")
    if isinstance(new_content, dict):
        body = new_content.get("body")
        if body is not None and str(body).strip():
            return str(body).strip()

    body = content.get("body")
    if body is not None and str(body).strip():
        return str(body).strip()

    for key in ("filename", "name", "title"):
        value = content.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _extract_event_text(event: Any) -> str:
    """Extract text from either a parsed event or a raw Matrix event."""
    if isinstance(event, dict):
        content = event.get("content")
        text = _extract_content_text(content)
        if text:
            return text
        return str(event.get("body") or "").strip()

    text = str(getattr(event, "body", "") or "").strip()
    if text:
        return text
    return _extract_content_text(getattr(event, "content", {}))


def _strip_edit_fallback(text: str) -> str:
    """Remove the legacy ``* `` prefix from an edit fallback body."""
    text = str(text or "").strip()
    if text.startswith("* "):
        return text[2:].lstrip()
    return text


async def _fetch_replace_target(adapter, room, event_id: str, event=None):
    """Fetch the event targeted by an ``m.replace`` relation if possible."""
    validated = getattr(event, "_validated_replace_target", None) if event else None
    if isinstance(validated, dict):
        return validated

    client = getattr(adapter, "client", None)
    get_event = getattr(client, "get_event", None)
    if not event_id or not callable(get_event):
        return None
    try:
        return await get_event(room.room_id, event_id)
    except Exception as exc:
        logger.debug(f"获取 m.replace 原始消息失败：{exc}")
        return None


def _extract_previous_content_text(event) -> str:
    """Use ``unsigned.prev_content`` as a local fallback for the quote."""
    unsigned = getattr(event, "unsigned", None)
    if not isinstance(unsigned, dict):
        return ""
    return _extract_content_text(unsigned.get("prev_content"))


def _replace_event_text(event, text: str) -> None:
    """Replace the event payload with the text sent to AstrBot."""
    content = getattr(event, "content", {})
    normalized_content = dict(content) if isinstance(content, dict) else {}
    normalized_content["body"] = text
    # The formatted body describes only the new text.  Keeping it would make
    # the receiver parse that body and discard the ``[quote] ->`` context.
    normalized_content.pop("format", None)
    normalized_content.pop("formatted_body", None)
    event.content = normalized_content
    event.body = text


async def _normalize_replace_event(adapter, room, event) -> bool:
    """Convert a validated edit into ``[quote] -> [new_text]``."""
    content = getattr(event, "content", {})
    if not isinstance(content, dict):
        return False

    relates_to = content.get("m.relates_to")
    if not (
        isinstance(relates_to, dict)
        and relates_to.get("rel_type") == REL_TYPE_REPLACE
    ):
        return False

    original_event_id = relates_to.get("event_id")
    original_event = await _fetch_replace_target(
        adapter,
        room,
        str(original_event_id or ""),
        event=event,
    )
    quote = _extract_event_text(original_event)
    if not quote:
        quote = _extract_previous_content_text(event)

    new_text = _strip_edit_fallback(_extract_event_text(event))
    _replace_event_text(event, f"[{quote}] -> [{new_text}]")
    logger.debug(
        f"m.replace 消息已转换为 quote 输入："
        f"{original_event_id or '<unknown>'} -> {getattr(event, 'event_id', '')}"
    )
    return True


__all__ = ["_normalize_replace_event"]

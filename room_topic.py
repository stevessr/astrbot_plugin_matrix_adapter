"""Matrix v1.15 / MSC3765 rich room-topic helpers."""

from typing import Any

M_TOPIC_CONTENT = "m.topic"
M_TEXT_CONTENT = "m.text"


def build_room_topic_content(
    topic: str,
    *,
    formatted_topic: str | None = None,
) -> dict[str, Any]:
    """Build a stable ``m.room.topic`` content object.

    The legacy ``topic`` string remains present for older clients.  A plain
    variant is always included in the stable ``m.topic`` block; optional HTML
    is placed first so rich-topic-aware clients may prefer it.
    """
    plain = str(topic or "")
    variants: list[dict[str, str]] = []
    if isinstance(formatted_topic, str) and formatted_topic:
        variants.append({"mimetype": "text/html", "body": formatted_topic})
    variants.append({"mimetype": "text/plain", "body": plain})
    return {
        "topic": plain,
        M_TOPIC_CONTENT: {M_TEXT_CONTENT: variants},
    }


def extract_room_topic(content: object) -> tuple[str, str | None]:
    """Return ``(plain_topic, html_topic)`` from stable or legacy content.

    Malformed/unknown variants are ignored.  The legacy ``topic`` field is the
    fallback when no understood plain variant is present.
    """
    if not isinstance(content, dict):
        return "", None

    legacy = content.get("topic")
    legacy_topic = legacy if isinstance(legacy, str) else ""
    block = content.get(M_TOPIC_CONTENT)
    variants = block.get(M_TEXT_CONTENT) if isinstance(block, dict) else None
    if not isinstance(variants, list):
        return legacy_topic, None

    plain_topic: str | None = None
    html_topic: str | None = None
    for variant in variants:
        if not isinstance(variant, dict):
            continue
        body = variant.get("body")
        if not isinstance(body, str):
            continue
        mimetype = variant.get("mimetype") or "text/plain"
        if mimetype == "text/html" and html_topic is None:
            html_topic = body
        elif mimetype == "text/plain" and plain_topic is None:
            plain_topic = body

    return (plain_topic if plain_topic is not None else legacy_topic), html_topic


__all__ = [
    "M_TOPIC_CONTENT",
    "M_TEXT_CONTENT",
    "build_room_topic_content",
    "extract_room_topic",
]

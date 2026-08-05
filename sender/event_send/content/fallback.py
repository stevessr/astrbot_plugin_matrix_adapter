"""Per-segment fallback rendering for Matrix event sending."""

import html
import json

from astrbot.api.message_components import (
    Face,
    Forward,
    Json,
    Node,
    Nodes,
    Poke,
    Unknown,
)

from .text import _summarize_components, _truncate_text


def _fallback_content_for_segment(segment) -> tuple[str, str | None]:
    if isinstance(segment, Face):
        return f"[face:{getattr(segment, 'id', '')}]".strip(), None
    if isinstance(segment, Poke):
        poke_type = getattr(segment, "type", "") or ""
        body = f"[poke:{poke_type}]" if poke_type else "[poke]"
        return body, None
    if isinstance(segment, Forward):
        forward_id = getattr(segment, "id", "") or ""
        body = f"[forward:{forward_id}]" if forward_id else "[forward]"
        return body, None
    if isinstance(segment, Node):
        name = getattr(segment, "name", "") or ""
        uin = getattr(segment, "uin", "") or ""
        prefix = " ".join(x for x in [name, f"({uin})" if uin else ""] if x).strip()
        summary = _summarize_components(getattr(segment, "content", []))
        body = " ".join(x for x in [prefix, summary] if x).strip()
        html_body = "<br>".join(
            [html.escape(line) for line in [prefix, summary] if line and line.strip()]
        )
        return f"[node] {body}".strip(), (
            f"<blockquote>{html_body}</blockquote>" if html_body else None
        )
    if isinstance(segment, Nodes):
        nodes = getattr(segment, "nodes", []) or []
        blocks: list[str] = []
        texts: list[str] = []
        for node in nodes:
            name = getattr(node, "name", "") or ""
            uin = getattr(node, "uin", "") or ""
            prefix = " ".join(x for x in [name, f"({uin})" if uin else ""] if x).strip()
            summary = _summarize_components(getattr(node, "content", []))
            body = " ".join(x for x in [prefix, summary] if x).strip()
            if body:
                texts.append(body)
                blocks.append(f"<blockquote>{html.escape(body)}</blockquote>")
        text_body = _truncate_text(" | ".join(texts), max_len=400)
        html_body = "<br>".join(blocks) if blocks else None
        return f"[nodes] {text_body}".strip(), html_body
    if isinstance(segment, Json):
        try:
            payload = json.dumps(segment.data, ensure_ascii=True, indent=2)
        except Exception:
            payload = str(segment.data)
        payload = _truncate_text(payload, max_len=800)
        body = _truncate_text(f"[json] {payload}", max_len=400)
        html_body = f"<pre><code>{html.escape(payload)}</code></pre>"
        return body, html_body
    if isinstance(segment, Unknown):
        text = getattr(segment, "text", "") or "[unknown]"
        return text, None
    return f"[{type(segment).__name__}]", None


__all__ = ["_fallback_content_for_segment"]

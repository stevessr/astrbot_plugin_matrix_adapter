"""Text truncation and component summarization helpers."""

from astrbot.api.message_components import Plain


def _truncate_text(text: str, max_len: int = 400) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 20] + "... (truncated)"


def _summarize_components(components: list, max_len: int = 300) -> str:
    parts: list[str] = []
    for comp in components or []:
        if isinstance(comp, Plain):
            parts.append(comp.text)
        else:
            parts.append(f"[{type(comp).__name__}]")
    return _truncate_text(" ".join(parts).strip(), max_len=max_len)


__all__ = ["_summarize_components", "_truncate_text"]

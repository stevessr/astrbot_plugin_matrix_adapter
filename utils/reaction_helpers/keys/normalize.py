"""Reaction-key token normalization."""

import re

_SHORTCODE_PATTERN = re.compile(r"^:?([A-Za-z0-9_+\-.]+):?$")


def normalize_shortcode_token(value: str) -> str:
    """Normalize ``:smile:`` / ``smile`` style tokens to bare shortcode text."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    match = _SHORTCODE_PATTERN.fullmatch(raw)
    if match:
        return match.group(1).strip().lower()
    return raw.strip(":").strip().lower()

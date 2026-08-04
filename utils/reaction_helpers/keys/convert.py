"""Best-effort Unicode emoji shortcode conversion."""

from .normalize import _SHORTCODE_PATTERN, normalize_shortcode_token


def _try_convert_emoji_shortcode(reaction_key: str) -> str | None:
    """Best-effort Unicode emoji shortcode conversion without hard dependency."""
    raw = str(reaction_key or "").strip()
    if not raw:
        return None

    token = normalize_shortcode_token(raw)
    looks_like_shortcode = bool(_SHORTCODE_PATTERN.fullmatch(raw)) or (
        raw.startswith(":") and raw.endswith(":") and len(raw) > 2
    )
    if not looks_like_shortcode and (not token or ":" not in raw):
        # Bare free-form keys / raw emoji stay unchanged.
        if not token or any(ord(ch) > 127 for ch in raw):
            return None

    try:
        from astrbot_plugin_matrix_sticker.emoji_shortcodes import (  # type: ignore
            _get_emoji_shortcodes,
            convert_emoji_shortcodes,
        )
    except Exception:
        return None

    if token:
        try:
            mapping = _get_emoji_shortcodes() or {}
            mapped = mapping.get(token)
            if isinstance(mapped, str) and mapped.strip():
                return mapped.strip()
        except Exception:
            pass

    for candidate in (raw, f":{token}:" if token else ""):
        if not candidate:
            continue
        try:
            converted = str(convert_emoji_shortcodes(candidate) or "").strip()
        except Exception:
            continue
        if converted and converted != candidate and ":" not in converted:
            return converted
    return None

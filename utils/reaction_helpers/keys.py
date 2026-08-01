"""Reaction-key normalization and resolver integration."""

from __future__ import annotations

import inspect
import re
from typing import Any

from astrbot.api import logger

from .registry import _REACTION_KEY_RESOLVERS

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


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def resolve_reaction_key(
    reaction: str,
    *,
    context: Any | None = None,
    room_id: str = "",
    platform_id: str = "",
    event: Any | None = None,
) -> str:
    """Resolve a reaction key, optionally via injected shortcode resolvers.

    Resolution order:
    1. already an ``mxc://`` key
    2. registered external resolvers (e.g. sticker plugin shortcode → mxc)
    3. optional Unicode emoji shortcode conversion
    4. original trimmed reaction text
    """
    reaction_key = str(reaction or "").strip()
    if not reaction_key:
        return ""
    if reaction_key.startswith("mxc://"):
        return reaction_key

    for resolver in list(_REACTION_KEY_RESOLVERS):
        try:
            result: Any = resolver(
                reaction_key,
                context=context,
                room_id=room_id,
                platform_id=platform_id,
                event=event,
            )
            result = await _maybe_await(result)
        except TypeError:
            # Older/simple resolvers may only accept the reaction string.
            try:
                result = await _maybe_await(resolver(reaction_key))
            except Exception as exc:
                logger.debug("Matrix reaction resolver failed: %s", exc)
                continue
        except Exception as exc:
            logger.debug("Matrix reaction resolver failed: %s", exc)
            continue
        if result is None:
            continue
        resolved = str(result).strip()
        if resolved:
            return resolved

    converted = _try_convert_emoji_shortcode(reaction_key)
    if converted:
        return converted
    return reaction_key


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

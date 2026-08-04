"""Reaction-key resolution via registered resolvers."""

import inspect
from typing import Any

from astrbot.api import logger

from ..registry import _REACTION_KEY_RESOLVERS
from .convert import _try_convert_emoji_shortcode


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

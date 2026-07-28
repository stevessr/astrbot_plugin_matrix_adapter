"""Helpers for Matrix reaction targeting and reaction-key normalization."""

from __future__ import annotations

import inspect
import re
import time
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime
from typing import Any

from astrbot.api import logger

ReactionKeyResolver = Callable[..., str | None | Awaitable[str | None]]

_REACTION_KEY_RESOLVERS: list[ReactionKeyResolver] = []
_SHORTCODE_PATTERN = re.compile(r"^:?([A-Za-z0-9_+\-.]+):?$")
_ISO_TZ_PATTERN = re.compile(r"([+-]\d{2}):(\d{2})$")


def register_reaction_key_resolver(resolver: ReactionKeyResolver) -> bool:
    """Register a reaction-key resolver. Duplicates are ignored."""
    if resolver is None or not callable(resolver):
        return False
    if resolver in _REACTION_KEY_RESOLVERS:
        return False
    _REACTION_KEY_RESOLVERS.append(resolver)
    return True


def unregister_reaction_key_resolver(resolver: ReactionKeyResolver) -> bool:
    """Unregister a previously registered reaction-key resolver."""
    try:
        _REACTION_KEY_RESOLVERS.remove(resolver)
    except ValueError:
        return False
    return True


def list_reaction_key_resolvers() -> list[ReactionKeyResolver]:
    """Return a copy of registered reaction-key resolvers."""
    return list(_REACTION_KEY_RESOLVERS)


def clear_reaction_key_resolvers() -> None:
    """Remove all registered reaction-key resolvers (primarily for tests)."""
    _REACTION_KEY_RESOLVERS.clear()


def parse_reaction_anchor_time_ms(value: object | None) -> int | None:
    """Parse an optional anchor time into Unix milliseconds.

    Accepts:
    - ``None`` / empty → ``None``
    - int/float Unix seconds or milliseconds
    - numeric strings
    - ISO-8601 datetime strings
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _normalize_unix_to_ms(float(value))

    raw = str(value).strip()
    if not raw:
        return None

    if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", raw):
        try:
            return _normalize_unix_to_ms(float(raw))
        except ValueError:
            return None

    candidate = raw.replace("Z", "+00:00")
    candidate = _ISO_TZ_PATTERN.sub(r"\1\2", candidate)
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return int(dt.timestamp() * 1000)


def _normalize_unix_to_ms(value: float) -> int:
    # Values below this threshold are treated as seconds.
    if abs(value) < 1_000_000_000_000:
        return int(value * 1000)
    return int(value)


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
            from .utils import MatrixUtils

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


def select_nearest_matching_event(
    events: Sequence[dict[str, Any]],
    message_content: str,
    *,
    anchor_time_ms: int | None = None,
) -> dict[str, Any] | None:
    """Pick the nearest event whose body exactly matches, else contains, the query.

    Matching priority:
    1. exact body match closest to ``anchor_time_ms``
    2. substring body match closest to ``anchor_time_ms``

    When ``anchor_time_ms`` is omitted, "nearest" falls back to the first match in
    the provided order (callers should pass newest-first history for that case).
    """
    query = str(message_content or "").strip()
    if not query:
        return None

    exact_candidates: list[tuple[int, int, dict[str, Any]]] = []
    contain_candidates: list[tuple[int, int, dict[str, Any]]] = []
    query_folded = query.casefold()

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type") or "")
        if event_type not in {"m.room.message", "m.sticker"}:
            continue
        text = extract_matrix_event_text(event)
        if not text:
            continue
        text_folded = text.casefold()
        if text_folded == query_folded:
            bucket = exact_candidates
        elif query_folded in text_folded:
            bucket = contain_candidates
        else:
            continue

        event_ts = event_origin_server_ts_ms(event)
        if anchor_time_ms is None or event_ts is None:
            distance = index
        else:
            distance = abs(event_ts - anchor_time_ms)
        bucket.append((distance, index, event))

    for bucket in (exact_candidates, contain_candidates):
        if not bucket:
            continue
        bucket.sort(key=lambda item: (item[0], item[1]))
        return bucket[0][2]
    return None


def default_anchor_time_ms(event: Any | None = None) -> int:
    """Resolve the default reaction search anchor time in milliseconds."""
    if event is not None:
        message_obj = getattr(event, "message_obj", None)
        for candidate in (
            getattr(message_obj, "timestamp", None),
            getattr(event, "created_at", None),
        ):
            parsed = parse_reaction_anchor_time_ms(candidate)
            if parsed is not None:
                # message_obj.timestamp is usually seconds; created_at is seconds float.
                return parsed
        raw_message = getattr(message_obj, "raw_message", None)
        if isinstance(raw_message, dict):
            raw_ts = event_origin_server_ts_ms(raw_message)
            if raw_ts is not None:
                return raw_ts
            nested = getattr(raw_message, "origin_server_ts", None)
            parsed = parse_reaction_anchor_time_ms(nested)
            if parsed is not None:
                return parsed
        elif raw_message is not None:
            raw_ts = event_origin_server_ts_ms(
                {
                    "origin_server_ts": getattr(raw_message, "origin_server_ts", None),
                }
            )
            if raw_ts is not None:
                return raw_ts
    return int(time.time() * 1000)


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


async def collect_room_message_events(
    client: Any,
    room_id: str,
    *,
    limit: int = 100,
    max_pages: int = 3,
) -> list[dict[str, Any]]:
    """Fetch recent room events newest-first for reaction targeting."""
    if client is None:
        return []
    room_messages = getattr(client, "room_messages", None)
    if not callable(room_messages):
        return []

    collected: list[dict[str, Any]] = []
    from_token: str | None = None
    pages = max(1, int(max_pages))
    page_limit = max(1, min(int(limit), 100))

    for _ in range(pages):
        try:
            raw_response = room_messages(
                room_id=room_id,
                from_token=from_token,
                direction="b",
                limit=page_limit,
            )
            response = await _maybe_await(raw_response)
        except TypeError:
            try:
                raw_response = room_messages(
                    room_id,
                    from_token,
                    None,
                    "b",
                    page_limit,
                )
                response = await _maybe_await(raw_response)
            except Exception as exc:
                logger.debug(
                    "Failed to load Matrix room messages for reaction: %s", exc
                )
                break
        except Exception as exc:
            logger.debug("Failed to load Matrix room messages for reaction: %s", exc)
            break

        if not isinstance(response, dict):
            break
        chunk = response.get("chunk") or []
        if not isinstance(chunk, list) or not chunk:
            break
        for item in chunk:
            if isinstance(item, dict):
                collected.append(item)
        if len(collected) >= limit:
            break
        end = response.get("end")
        if not end or end == from_token:
            break
        from_token = str(end)
    return collected[:limit]


async def find_room_event_for_reaction(
    client: Any,
    room_id: str,
    message_content: str,
    *,
    anchor_time_ms: int | None = None,
    limit: int = 100,
    max_pages: int = 3,
) -> dict[str, Any] | None:
    """Find the nearest matching room event for a content-based reaction."""
    events = await collect_room_message_events(
        client,
        room_id,
        limit=limit,
        max_pages=max_pages,
    )
    return select_nearest_matching_event(
        events,
        message_content,
        anchor_time_ms=anchor_time_ms,
    )

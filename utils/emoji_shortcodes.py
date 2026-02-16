"""
Emoji shortcode conversion helpers with remote fetch and local cache.

Examples:
    :smile: -> 😄
    :thumbsup: -> 👍
    :heart: -> ❤️
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path

from astrbot.api import logger
from astrbot.api.star import StarTools

_SHORTCODE_PATTERN = re.compile(r"(?<!\\):([a-zA-Z0-9_+\-]+):")

_DEFAULT_SHORTCODES_URLS = (
    "https://raw.githubusercontent.com/iamcal/emoji-data/master/emoji.json",
    "https://raw.githubusercontent.com/github/gemoji/master/db/emoji.json",
)
_SHORTCODES_URL_ENV = "MATRIX_EMOJI_SHORTCODES_URL"
_SHORTCODE_CACHE_FILENAME = "emoji_shortcodes_cache.json"

# Fallback map when remote source/cache is unavailable.
_FALLBACK_EMOJI_SHORTCODES: dict[str, str] = {
    "100": "💯",
    "+1": "👍",
    "-1": "👎",
    "angry": "😠",
    "astonished": "😲",
    "beer": "🍺",
    "beers": "🍻",
    "blush": "😊",
    "boom": "💥",
    "broken_heart": "💔",
    "bug": "🐛",
    "bulb": "💡",
    "calendar": "📅",
    "check": "✅",
    "clap": "👏",
    "cold_sweat": "😰",
    "confounded": "😖",
    "confused": "😕",
    "cry": "😢",
    "dizzy": "💫",
    "dog": "🐶",
    "droplet": "💧",
    "eyes": "👀",
    "face_with_raised_eyebrow": "🤨",
    "fire": "🔥",
    "flushed": "😳",
    "grin": "😁",
    "grinning": "😀",
    "grey_exclamation": "❕",
    "grey_question": "❔",
    "hand": "✋",
    "heart": "❤️",
    "heart_eyes": "😍",
    "hearts": "♥️",
    "heavy_check_mark": "✔️",
    "heavy_multiplication_x": "✖️",
    "hushed": "😯",
    "icecream": "🍦",
    "joy": "😂",
    "kissing": "😗",
    "kissing_closed_eyes": "😚",
    "kissing_heart": "😘",
    "kissing_smiling_eyes": "😙",
    "laughing": "😆",
    "loudspeaker": "📢",
    "love": "❤️",
    "mask": "😷",
    "memo": "📝",
    "metal": "🤘",
    "moon": "🌙",
    "muscle": "💪",
    "neutral_face": "😐",
    "no_mouth": "😶",
    "ok": "👌",
    "ok_hand": "👌",
    "open_mouth": "😮",
    "party": "🥳",
    "pensive": "😔",
    "persevere": "😣",
    "point_down": "👇",
    "point_left": "👈",
    "point_right": "👉",
    "point_up": "☝️",
    "point_up_2": "👆",
    "pray": "🙏",
    "question": "❓",
    "rage": "😡",
    "raised_hand": "✋",
    "raised_hands": "🙌",
    "relaxed": "☺️",
    "relieved": "😌",
    "rocket": "🚀",
    "roll_eyes": "🙄",
    "rofl": "🤣",
    "sad": "😢",
    "scream": "😱",
    "scream_cat": "🙀",
    "see_no_evil": "🙈",
    "shushing_face": "🤫",
    "sleeping": "😴",
    "slight_frown": "🙁",
    "slight_smile": "🙂",
    "smile": "😄",
    "smiley": "😃",
    "smirk": "😏",
    "sob": "😭",
    "sparkles": "✨",
    "star": "⭐",
    "stuck_out_tongue": "😛",
    "stuck_out_tongue_closed_eyes": "😝",
    "stuck_out_tongue_winking_eye": "😜",
    "sunglasses": "😎",
    "sweat": "😓",
    "sweat_smile": "😅",
    "thinking": "🤔",
    "thumbsdown": "👎",
    "thumbsup": "👍",
    "tired_face": "😫",
    "triumph": "😤",
    "unamused": "😒",
    "upside_down": "🙃",
    "v": "✌️",
    "warning": "⚠️",
    "wave": "👋",
    "white_check_mark": "✅",
    "wink": "😉",
    "x": "❌",
    "yum": "😋",
}

_EMOJI_SHORTCODES: dict[str, str] | None = None
_SHORTCODE_CONVERSION_ENABLED = True
_SHORTCODE_CACHE_PATH: Path | None = None


def _default_cache_path() -> Path:
    try:
        base_dir = StarTools.get_data_dir("astrbot_plugin_matrix_adapter")
    except Exception:
        base_dir = Path("./data/astrbot_plugin_matrix_adapter")
    return Path(base_dir) / _SHORTCODE_CACHE_FILENAME


def configure_emoji_shortcodes(
    enabled: bool = True,
    cache_path: str | Path | None = None,
) -> None:
    """
    Configure shortcode conversion behavior.

    Args:
        enabled: Whether shortcode conversion is enabled.
        cache_path: Optional local cache file path.
    """
    global _SHORTCODE_CONVERSION_ENABLED
    global _SHORTCODE_CACHE_PATH
    global _EMOJI_SHORTCODES

    _SHORTCODE_CONVERSION_ENABLED = bool(enabled)
    _SHORTCODE_CACHE_PATH = Path(cache_path) if cache_path else _default_cache_path()
    _EMOJI_SHORTCODES = None


def _get_cache_path() -> Path:
    return _SHORTCODE_CACHE_PATH or _default_cache_path()


def _normalize_shortcode_map(data: dict) -> dict[str, str]:
    result: dict[str, str] = {}
    if not isinstance(data, dict):
        return result
    for key, value in data.items():
        if not isinstance(key, str):
            continue
        if not isinstance(value, str) or not value.strip():
            continue
        normalized = key.strip().lower().strip(":")
        if normalized:
            result[normalized] = value
    return result


def _load_shortcodes_from_cache() -> dict[str, str]:
    cache_path = _get_cache_path()
    if not cache_path.exists():
        return {}
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and isinstance(payload.get("shortcodes"), dict):
            data = payload["shortcodes"]
        elif isinstance(payload, dict):
            # Backward compatible for plain dict cache.
            data = payload
        else:
            return {}
        return _normalize_shortcode_map(data)
    except Exception as e:
        logger.warning(f"Failed to read emoji shortcode cache {cache_path}: {e}")
        return {}


def _save_shortcodes_to_cache(shortcodes: dict[str, str]) -> None:
    cache_path = _get_cache_path()
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "count": len(shortcodes),
            "shortcodes": shortcodes,
        }
        cache_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception as e:
        logger.warning(f"Failed to write emoji shortcode cache {cache_path}: {e}")


def _unified_to_emoji(unified: str) -> str:
    if not isinstance(unified, str) or not unified:
        return ""
    chars: list[str] = []
    for part in unified.split("-"):
        part = part.strip()
        if not part:
            continue
        try:
            chars.append(chr(int(part, 16)))
        except Exception:
            return ""
    return "".join(chars)


def _parse_remote_shortcodes(payload) -> dict[str, str]:
    """
    Parse remote payload to shortcode->emoji map.

    Supported formats:
    - iamcal emoji-data list objects with unified/non_qualified + short_names
    - github/gemoji list objects with emoji + aliases
    - direct dict mapping shortcode -> emoji
    """
    result: dict[str, str] = {}

    if isinstance(payload, dict):
        for key, value in payload.items():
            if not isinstance(key, str):
                continue
            if not isinstance(value, str) or not value.strip():
                continue
            norm = key.strip().lower().strip(":")
            if norm:
                result[norm] = value
        return result

    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue

            # github/gemoji format: {"emoji": "😀", "aliases": ["grinning", ...]}
            emoji_char = item.get("emoji")
            aliases = item.get("aliases")
            if isinstance(emoji_char, str) and emoji_char and isinstance(aliases, list):
                for alias in aliases:
                    if isinstance(alias, str) and alias.strip():
                        normalized = alias.lower().strip(":")
                        if normalized:
                            result[normalized] = emoji_char
                            result[normalized.replace("-", "_")] = emoji_char

            # iamcal format: {"unified": "...", "short_names": [...]}
            unified = item.get("unified") or item.get("non_qualified")
            emoji = _unified_to_emoji(unified)
            if not emoji:
                continue

            names: set[str] = set()
            short_name = item.get("short_name")
            if isinstance(short_name, str) and short_name.strip():
                names.add(short_name.strip())

            short_names = item.get("short_names")
            if isinstance(short_names, list):
                for short in short_names:
                    if isinstance(short, str) and short.strip():
                        names.add(short.strip())

            for name in names:
                normalized = name.lower().strip(":")
                if not normalized:
                    continue
                result[normalized] = emoji
                result[normalized.replace("-", "_")] = emoji

        return result

    return result


def _fetch_remote_shortcodes() -> dict[str, str]:
    env_urls = os.environ.get(_SHORTCODES_URL_ENV, "").strip()
    urls = (
        [u.strip() for u in env_urls.split(",") if u.strip()]
        if env_urls
        else list(_DEFAULT_SHORTCODES_URLS)
    )

    merged: dict[str, str] = {}
    loaded_sources = 0

    for url in urls:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "astrbot-matrix-adapter/emoji-shortcodes",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                data = response.read()
            payload = json.loads(data.decode("utf-8"))
            shortcodes = _parse_remote_shortcodes(payload)
            if shortcodes:
                merged.update(shortcodes)
                loaded_sources += 1
                logger.debug(
                    f"Emoji shortcodes loaded from {url} (count={len(shortcodes)})"
                )
        except Exception as e:
            logger.warning(
                f"Failed to load emoji shortcodes from remote source {url}: {e}"
            )

    if loaded_sources > 1:
        logger.debug(
            f"Emoji shortcodes merged from {loaded_sources} sources (count={len(merged)})"
        )
    return merged


def warmup_emoji_shortcodes(
    force_refresh: bool = False, fetch_remote: bool = False
) -> dict[str, str]:
    """
    Warm up shortcode table from cache and optional remote source.

    Behavior:
    - Default (`fetch_remote=False`): only load local cache, fallback to built-in table.
    - Remote (`fetch_remote=True`): fetch online table, merge+cache it.
    """
    global _EMOJI_SHORTCODES

    if not _SHORTCODE_CONVERSION_ENABLED:
        _EMOJI_SHORTCODES = {}
        return _EMOJI_SHORTCODES

    cached_shortcodes = _load_shortcodes_from_cache()
    should_fetch_remote = bool(fetch_remote) or bool(force_refresh)

    if should_fetch_remote:
        remote_shortcodes = _fetch_remote_shortcodes()
        if remote_shortcodes:
            merged_shortcodes = dict(_FALLBACK_EMOJI_SHORTCODES)
            merged_shortcodes.update(remote_shortcodes)
            _EMOJI_SHORTCODES = merged_shortcodes
            _save_shortcodes_to_cache(merged_shortcodes)
            return _EMOJI_SHORTCODES

    if cached_shortcodes:
        _EMOJI_SHORTCODES = cached_shortcodes
    else:
        _EMOJI_SHORTCODES = dict(_FALLBACK_EMOJI_SHORTCODES)
    return _EMOJI_SHORTCODES


def _get_emoji_shortcodes() -> dict[str, str]:
    global _EMOJI_SHORTCODES
    if _EMOJI_SHORTCODES is not None:
        return _EMOJI_SHORTCODES
    return warmup_emoji_shortcodes(force_refresh=False, fetch_remote=False)


def convert_emoji_shortcodes(text: str) -> str:
    """
    Convert emoji shortcodes to Unicode emoji.

    - Unknown shortcodes are preserved as-is.
    - Escaped forms like `\\:smile:` stay as `:smile:`.
    """
    if not isinstance(text, str):
        return ""
    if not _SHORTCODE_CONVERSION_ENABLED or ":" not in text:
        return text

    emoji_shortcodes = _get_emoji_shortcodes()
    if not emoji_shortcodes:
        return text

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1).strip().lower()
        return emoji_shortcodes.get(key, match.group(0))

    converted = _SHORTCODE_PATTERN.sub(_replace, text)
    return converted.replace("\\:", ":")

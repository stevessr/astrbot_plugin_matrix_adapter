"""Reaction search time parsing helpers."""

import re
from datetime import datetime

_ISO_TZ_PATTERN = re.compile(r"([+-]\d{2}):(\d{2})$")


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

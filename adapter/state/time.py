"""Time helpers for runtime state timestamps."""

from datetime import datetime, timezone


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = ["_utc_now_iso"]

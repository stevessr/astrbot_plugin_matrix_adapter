"""Runtime error entry model."""

from dataclasses import dataclass, field

from .time import _utc_now_iso


@dataclass
class MatrixRuntimeErrorEntry:
    category: str
    message: str
    ts: str = field(default_factory=_utc_now_iso)


__all__ = ["MatrixRuntimeErrorEntry"]

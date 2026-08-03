"""Composable reaction history collection and matching helpers."""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

from astrbot.api import logger

from ....constants import M_ROOM_MESSAGE, M_STICKER
from ..events import event_origin_server_ts_ms, extract_matrix_event_text
from ..keys import _maybe_await
from ..time import parse_reaction_anchor_time_ms
from .history import collect_room_message_events, find_room_event_for_reaction
from .matching import default_anchor_time_ms, select_nearest_matching_event

__all__ = [
    "Any",
    "M_ROOM_MESSAGE",
    "M_STICKER",
    "Sequence",
    "collect_room_message_events",
    "default_anchor_time_ms",
    "event_origin_server_ts_ms",
    "extract_matrix_event_text",
    "find_room_event_for_reaction",
    "logger",
    "_maybe_await",
    "parse_reaction_anchor_time_ms",
    "select_nearest_matching_event",
    "time",
]

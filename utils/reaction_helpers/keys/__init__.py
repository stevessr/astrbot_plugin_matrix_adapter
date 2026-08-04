"""Reaction-key normalization and resolver integration.

Public symbols re-exported for backward compatibility.
"""

from .convert import _try_convert_emoji_shortcode
from .normalize import _SHORTCODE_PATTERN, normalize_shortcode_token
from .resolve import _maybe_await, resolve_reaction_key

__all__ = [
    "_SHORTCODE_PATTERN",
    "_maybe_await",
    "_try_convert_emoji_shortcode",
    "normalize_shortcode_token",
    "resolve_reaction_key",
]

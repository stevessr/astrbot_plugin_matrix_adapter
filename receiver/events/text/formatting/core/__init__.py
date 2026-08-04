"""Formatted Matrix text -> message chain conversion."""

from .caption import should_append_caption
from .core import append_formatted_text

__all__ = ["append_formatted_text", "should_append_caption"]

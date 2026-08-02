"""Layered Matrix adapter send operations."""

from ...config.plugin import get_plugin_config
from .formatting import (
    _looks_like_markdown,
    build_message_chain,
    format_plain_segment,
)
from .mixin import MatrixAdapterSendMixin

__all__ = [
    "MatrixAdapterSendMixin",
    "get_plugin_config",
    "_looks_like_markdown",
    "build_message_chain",
    "format_plain_segment",
]

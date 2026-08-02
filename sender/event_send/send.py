"""Backward-compatible entry point for Matrix event message dispatch."""

from .content import (
    _fallback_content_for_segment,
    _is_media_security_validation_error,
    _is_poll_component,
    _is_sticker_component,
    _summarize_components,
    _truncate_text,
)
from .dispatch.core import send_with_client_impl

__all__ = [
    "send_with_client_impl",
    "_fallback_content_for_segment",
    "_is_media_security_validation_error",
    "_is_poll_component",
    "_is_sticker_component",
    "_summarize_components",
    "_truncate_text",
]

"""Component detection and fallback rendering for Matrix event sending."""

from .check import _is_poll_component, _is_sticker_component
from .error import _is_media_security_validation_error
from .fallback import _fallback_content_for_segment
from .text import _summarize_components, _truncate_text

__all__ = [
    "_fallback_content_for_segment",
    "_is_media_security_validation_error",
    "_is_poll_component",
    "_is_sticker_component",
    "_summarize_components",
    "_truncate_text",
]

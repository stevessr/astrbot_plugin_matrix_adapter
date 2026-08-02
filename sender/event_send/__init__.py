"""Split implementation for Matrix event message sending."""

from importlib import import_module

__all__ = [
    "send_with_client_impl",
    "_fallback_content_for_segment",
    "_is_media_security_validation_error",
    "_is_poll_component",
    "_is_sticker_component",
    "_summarize_components",
    "_truncate_text",
]


def __getattr__(name: str):
    if name == "send_with_client_impl":
        return import_module(".dispatch.core", __name__).send_with_client_impl
    if name in __all__[1:]:
        return getattr(import_module(".content", __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

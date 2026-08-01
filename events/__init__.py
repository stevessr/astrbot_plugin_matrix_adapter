"""Matrix event-domain helpers and platform event integration."""

from importlib import import_module

__all__ = [
    "CallEventConfig",
    "classify_call_event",
    "format_call_event_text",
    "is_call_event_type",
    "should_surface_call_event",
    "MatrixPlatformEvent",
    "MatrixPlatformEventStreamMixin",
]

_EXPORTS = {
    "CallEventConfig": (".call", "CallEventConfig"),
    "classify_call_event": (".call", "classify_call_event"),
    "format_call_event_text": (".call", "format_call_event_text"),
    "is_call_event_type": (".call", "is_call_event_type"),
    "should_surface_call_event": (".call", "should_surface_call_event"),
    "MatrixPlatformEvent": (".matrix", "MatrixPlatformEvent"),
    "MatrixPlatformEventStreamMixin": (".matrix", "MatrixPlatformEventStreamMixin"),
}


def __getattr__(name: str):
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    return getattr(import_module(module_name, __name__), attribute_name)

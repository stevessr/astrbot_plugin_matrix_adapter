"""Matrix system event helpers."""

from importlib import import_module

__all__ = [
    "CallEventConfig",
    "classify_call_event",
    "format_call_event_text",
    "is_call_event_type",
    "should_surface_call_event",
]

_EXPORTS = {name: (".call", name) for name in __all__}


def __getattr__(name: str):
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    return getattr(import_module(module_name, __name__), attribute_name)

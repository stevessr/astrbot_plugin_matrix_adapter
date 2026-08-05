"""Component duck-typing detection helpers."""

from ....sticker import Sticker
from ..components import Poll


def _is_sticker_component(obj) -> bool:
    """Check if object is a Sticker-like component via duck-typing."""
    if isinstance(obj, Sticker):
        return True
    class_name = type(obj).__name__
    if class_name != "Sticker":
        return False
    required_attrs = ["body", "url", "info", "to_matrix_content"]
    return all(hasattr(obj, attr) for attr in required_attrs)


def _is_poll_component(obj) -> bool:
    """Check if object is a Poll-like component via duck-typing."""
    if isinstance(obj, Poll):
        return True
    class_name = type(obj).__name__
    if class_name != "Poll":
        return False
    required_attrs = ["question", "answers"]
    return all(hasattr(obj, attr) for attr in required_attrs)


__all__ = ["_is_poll_component", "_is_sticker_component"]

"""Layered Matrix streaming event helpers."""

from .messages import MatrixPlatformEventMessagesMixin
from .typing import MatrixPlatformEventTypingMixin


class MatrixPlatformEventStreamMixin(
    MatrixPlatformEventMessagesMixin,
    MatrixPlatformEventTypingMixin,
):
    """Compose Matrix live-message and typing stream behavior."""

    pass


__all__ = [
    "MatrixPlatformEventMessagesMixin",
    "MatrixPlatformEventStreamMixin",
    "MatrixPlatformEventTypingMixin",
]

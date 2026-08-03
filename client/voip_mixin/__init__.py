"""Composable Matrix VoIP helper operations."""

from typing import Any  # noqa: F401

from .turn import VoipTurnMixin


class VoipMixin(VoipTurnMixin):
    """VoIP methods for Matrix client."""

    pass


# Preserve direct method attributes exposed by the former mixin.
VoipMixin.get_turn_server = VoipTurnMixin.__dict__["get_turn_server"]


__all__ = ["Any", "VoipMixin"]

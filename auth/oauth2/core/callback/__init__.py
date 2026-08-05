"""Unified OAuth2 callback server lifecycle."""

from .handler import _OAuth2CallbackHandlerMixin
from .state import _OAuth2CallbackStateMixin
from .wait import _OAuth2CallbackWaitMixin


class OAuth2CallbackServer(
    _OAuth2CallbackStateMixin,
    _OAuth2CallbackHandlerMixin,
    _OAuth2CallbackWaitMixin,
):
    """Unified webhook callback controller for OAuth2 flows."""


__all__ = ["OAuth2CallbackServer"]

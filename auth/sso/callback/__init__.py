"""Composable Matrix SSO callback handling and lifecycle helpers."""

import asyncio

from ...oauth2.core import (  # noqa: F401
    _get_query_param,
    _get_request_query_params,
    _has_query_param,
    _log,
)
from .handling import SSOCallbackHandlingMixin
from .lifecycle import SSOCallbackLifecycleMixin


class SSOCallbackServer(SSOCallbackLifecycleMixin, SSOCallbackHandlingMixin):
    """Unified webhook callback controller for Matrix SSO callbacks."""

    pass


# Preserve direct method attributes exposed by the former callback server.
SSOCallbackServer.__init__ = SSOCallbackLifecycleMixin.__dict__["__init__"]
SSOCallbackServer.handle_callback = SSOCallbackHandlingMixin.__dict__["handle_callback"]
SSOCallbackServer.start = SSOCallbackLifecycleMixin.__dict__["start"]
SSOCallbackServer.stop = SSOCallbackLifecycleMixin.__dict__["stop"]
SSOCallbackServer.prepare_callback = SSOCallbackLifecycleMixin.__dict__[
    "prepare_callback"
]
SSOCallbackServer.wait_for_callback = SSOCallbackLifecycleMixin.__dict__[
    "wait_for_callback"
]


__all__ = ["SSOCallbackServer", "asyncio"]

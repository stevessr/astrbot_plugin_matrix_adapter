"""Composable OAuth2 authorization, callback, device, and refresh helpers."""

from typing import Any
from urllib.parse import urlencode

import aiohttp

from ..core import OAuth2CallbackServer
from .callback import MatrixOAuth2FlowCallbackMixin
from .device import MatrixOAuth2DeviceGrantMixin
from .login import MatrixOAuth2FlowLoginMixin
from .refresh import MatrixOAuth2FlowRefreshMixin


class MatrixOAuth2FlowMixin(
    MatrixOAuth2DeviceGrantMixin,
    MatrixOAuth2FlowLoginMixin,
    MatrixOAuth2FlowCallbackMixin,
    MatrixOAuth2FlowRefreshMixin,
):
    """Run browser/device authorization, webhook callbacks, and token refresh."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MatrixOAuth2FlowMixin.login = MatrixOAuth2FlowLoginMixin.__dict__["login"]
MatrixOAuth2FlowMixin.login_device = MatrixOAuth2DeviceGrantMixin.__dict__["login_device"]
MatrixOAuth2FlowMixin._finish_device_login = MatrixOAuth2DeviceGrantMixin.__dict__[
    "_finish_device_login"
]
MatrixOAuth2FlowMixin.handle_webhook_callback = MatrixOAuth2FlowCallbackMixin.__dict__[
    "handle_webhook_callback"
]
MatrixOAuth2FlowMixin.refresh_access_token = MatrixOAuth2FlowRefreshMixin.__dict__[  # noqa: E501
    "refresh_access_token"
]


__all__ = [
    "Any",
    "MatrixOAuth2FlowMixin",
    "OAuth2CallbackServer",
    "aiohttp",
    "urlencode",
]

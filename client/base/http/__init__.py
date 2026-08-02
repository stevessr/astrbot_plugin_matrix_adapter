"""Composable core HTTP request functionality for the Matrix client."""

import asyncio  # noqa: F401
from typing import Any  # noqa: F401

import aiohttp  # noqa: F401

from astrbot.api import logger  # noqa: F401

from ....config.plugin import get_plugin_config  # noqa: F401
from ....constants import (
    ERROR_TRUNCATE_LENGTH_200,  # noqa: F401
    HTTP_ERROR_STATUS_400,  # noqa: F401
)
from ..errors import MatrixAPIError  # noqa: F401
from .lifecycle import MatrixHTTPSessionMixin
from .request import MatrixHTTPRequestMixin
from .timeout import MatrixHTTPTimeoutMixin


class MatrixClientBase(
    MatrixHTTPSessionMixin,
    MatrixHTTPTimeoutMixin,
    MatrixHTTPRequestMixin,
):
    """
    Base class for Matrix HTTP client
    Provides core HTTP request functionality
    """

    pass


# Preserve direct class attributes and method descriptors exposed by the former base.
MatrixClientBase._DEFAULT_HTTP_TIMEOUT_SECONDS = MatrixHTTPTimeoutMixin.__dict__[
    "_DEFAULT_HTTP_TIMEOUT_SECONDS"
]
MatrixClientBase._MIN_HTTP_TIMEOUT_SECONDS = MatrixHTTPTimeoutMixin.__dict__[
    "_MIN_HTTP_TIMEOUT_SECONDS"
]
MatrixClientBase._MAX_HTTP_TIMEOUT_SECONDS = MatrixHTTPTimeoutMixin.__dict__[
    "_MAX_HTTP_TIMEOUT_SECONDS"
]
MatrixClientBase.__init__ = MatrixHTTPSessionMixin.__dict__["__init__"]
MatrixClientBase._normalize_http_timeout_seconds = MatrixHTTPTimeoutMixin.__dict__[
    "_normalize_http_timeout_seconds"
]
MatrixClientBase.get_http_timeout_seconds = MatrixHTTPTimeoutMixin.__dict__[
    "get_http_timeout_seconds"
]
MatrixClientBase._build_http_timeout = MatrixHTTPTimeoutMixin.__dict__[
    "_build_http_timeout"
]
MatrixClientBase._ensure_session = MatrixHTTPSessionMixin.__dict__["_ensure_session"]
MatrixClientBase.close = MatrixHTTPSessionMixin.__dict__["close"]
MatrixClientBase._get_headers = MatrixHTTPRequestMixin.__dict__["_get_headers"]
MatrixClientBase._request = MatrixHTTPRequestMixin.__dict__["_request"]


__all__ = ["MatrixClientBase"]

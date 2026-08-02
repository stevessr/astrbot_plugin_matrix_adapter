"""HTTP timeout normalization and construction helpers."""

from typing import Any

import aiohttp

from .compat import get_plugin_config


class MatrixHTTPTimeoutMixin:
    """Normalize configured HTTP timeout values."""

    _DEFAULT_HTTP_TIMEOUT_SECONDS = 120.0
    _MIN_HTTP_TIMEOUT_SECONDS = 5.0
    _MAX_HTTP_TIMEOUT_SECONDS = 600.0

    @classmethod
    def _normalize_http_timeout_seconds(cls, value: Any) -> float:
        try:
            timeout = float(value)
        except Exception:
            timeout = cls._DEFAULT_HTTP_TIMEOUT_SECONDS
        if timeout < cls._MIN_HTTP_TIMEOUT_SECONDS:
            timeout = cls._MIN_HTTP_TIMEOUT_SECONDS
        if timeout > cls._MAX_HTTP_TIMEOUT_SECONDS:
            timeout = cls._MAX_HTTP_TIMEOUT_SECONDS
        return timeout

    def get_http_timeout_seconds(self) -> float:
        try:
            configured = get_plugin_config().http_timeout_seconds
        except Exception:
            configured = self._DEFAULT_HTTP_TIMEOUT_SECONDS
        return self._normalize_http_timeout_seconds(configured)

    def _build_http_timeout(
        self, override_seconds: int | None = None
    ) -> aiohttp.ClientTimeout:
        seconds = (
            override_seconds
            if override_seconds is not None
            else self.get_http_timeout_seconds()
        )
        return aiohttp.ClientTimeout(
            total=seconds,
            connect=seconds,
            sock_connect=seconds,
            sock_read=seconds,
        )

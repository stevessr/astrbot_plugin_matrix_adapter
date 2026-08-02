"""HTTP client session lifecycle helpers."""

import asyncio

import aiohttp


class MatrixHTTPSessionMixin:
    """Initialize, lazily create, and close the HTTP session."""

    def __init__(self, homeserver: str):
        """
        Initialize Matrix HTTP client base

        Args:
            homeserver: Matrix homeserver URL (e.g., https://matrix.org)
        """
        self.homeserver = homeserver.rstrip("/")
        self.access_token: str | None = None
        self.user_id: str | None = None
        self.device_id: str | None = None
        self.session: aiohttp.ClientSession | None = None
        self._session_lock = asyncio.Lock()
        self._next_batch: str | None = None

    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self.session is None or self.session.closed:
            async with self._session_lock:
                if self.session is None or self.session.closed:  # double-check
                    self.session = aiohttp.ClientSession(
                        timeout=self._build_http_timeout()
                    )

    async def close(self):
        """Close the HTTP session"""
        if self.session and not self.session.closed:
            await self.session.close()

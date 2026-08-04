"""Direct auth metadata discovery."""

from ...core import _log


async def _fetch_auth_metadata(session, self):
    """Try the direct auth_metadata endpoint; return metadata dict or None."""
    auth_metadata_url = f"{self.homeserver}/_matrix/client/v1/auth_metadata"
    _log("debug", f"Fetching {auth_metadata_url}")

    try:
        async with session.get(auth_metadata_url) as response:
            if response.status == 200:
                auth_metadata = await response.json()
                _log("debug", f"Auth metadata: {auth_metadata}")
                return self._apply_discovered_oauth_metadata(auth_metadata)
            _log(
                "debug",
                "Direct auth metadata unavailable, falling back to "
                f"/.well-known discovery (HTTP {response.status})",
            )
    except Exception as e:
        _log(
            "warning",
            "Direct auth metadata discovery failed, falling back to "
            f"/.well-known discovery: {e}",
        )
    return None

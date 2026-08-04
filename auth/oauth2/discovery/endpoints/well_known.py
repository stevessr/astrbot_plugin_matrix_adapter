"""Well-known based OAuth2 issuer discovery."""

from ...core import _log


async def _discover_via_well_known(session, self):
    """Fetch /.well-known/matrix/client and extract the auth config."""
    well_known_url = f"{self.homeserver}/.well-known/matrix/client"
    _log("debug", f"Fetching {well_known_url}")

    async with session.get(well_known_url, allow_redirects=True) as response:
        if response.status == 404:
            raise Exception(
                "Server does not have /.well-known/matrix/client endpoint. "
                "OAuth2 authentication is not supported by this homeserver. "
                "Please use 'password' or 'token' authentication instead."
            )
        elif response.status != 200:
            raise Exception(f"Failed to fetch well-known: HTTP {response.status}")

        well_known_data = await response.json()
        _log("debug", f"Well-known data: {well_known_data}")

        auth_config = well_known_data.get("m.authentication", {})

        if not auth_config:
            auth_config = well_known_data.get("org.matrix.msc4143.authentication", {})

        if not auth_config:
            auth_config = well_known_data.get("org.matrix.msc2965.authentication", {})

        if not auth_config:
            _log(
                "error",
                "❌ Failed to discover OAuth2 configuration: No authentication configuration found in well-known.",
            )
            _log(
                "error",
                "💡 This homeserver does not support OAuth2 authentication.",
            )
            _log(
                "error",
                "💡 Please change matrix_auth_method to 'password' or 'token' in your configuration.",
            )
            _log(
                "debug",
                f"Available keys in well-known: {list(well_known_data.keys())}",
            )
            _log(
                "debug",
                "Authentication keys checked: m.authentication, org.matrix.msc4143.authentication, org.matrix.msc2965.authentication",
            )
            raise Exception(
                "No authentication configuration found in well-known. "
                "OAuth2 authentication is not supported by this homeserver. "
                "Please use 'password' or 'token' authentication instead."
            )

        issuer = auth_config.get("issuer")
        if not issuer:
            raise Exception(
                "No issuer found in m.authentication. "
                "OAuth2 authentication is not properly configured on this homeserver. "
                "Please use 'password' or 'token' authentication instead."
            )

        self.issuer = issuer
        _log("info", f"Found OAuth2 issuer: {issuer}")

        if not issuer.endswith("/"):
            issuer = issuer + "/"
        return issuer, auth_config

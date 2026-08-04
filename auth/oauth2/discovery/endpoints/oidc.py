"""OIDC configuration fetching from the discovered issuer."""

from ...core import _log


async def _fetch_oidc_config(session, issuer: str, auth_config: dict) -> dict:
    """Fetch and validate the OIDC configuration for the issuer."""
    oidc_config_url = f"{issuer}.well-known/openid-configuration"
    _log("debug", f"Fetching OIDC configuration from {oidc_config_url}")

    async with session.get(oidc_config_url) as oidc_response:
        if oidc_response.status != 200:
            _log(
                "error",
                f"Failed to fetch OIDC configuration: HTTP {oidc_response.status}",
            )
            _log("error", f"URL requested: {oidc_config_url}")
            try:
                error_text = await oidc_response.text()
                _log("error", f"Response body: {error_text[:200]}")
            except Exception:
                pass
            raise Exception(
                f"Failed to fetch OIDC configuration: HTTP {oidc_response.status}"
            )

        oidc_config = await oidc_response.json()
        _log("debug", f"OIDC configuration: {oidc_config}")
        return oidc_config

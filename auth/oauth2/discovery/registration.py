"""Register OAuth2 clients dynamically."""

import ipaddress
from urllib.parse import urlsplit

import aiohttp

from ..core import _log

_DEFAULT_CLIENT_URI = "https://github.com/Soulter/AstrBot"


def _is_loopback_host(hostname: str | None) -> bool:
    if not hostname:
        return False
    normalized = hostname.strip().lower().rstrip(".")
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _registration_client_identity(redirect_uri: str | None) -> tuple[str, str]:
    """Return a Matrix-compliant ``(client_uri, application_type)`` pair."""
    if not redirect_uri:
        return _DEFAULT_CLIENT_URI, "native"

    parsed = urlsplit(redirect_uri)
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("OAuth redirect_uri must contain a valid host without userinfo")

    scheme = parsed.scheme.lower()
    if scheme == "https":
        # Client metadata URIs must share the redirect URI's host (or parent
        # domain). Using the callback origin keeps dynamic registration valid
        # for AstrBot deployments on arbitrary domains.
        return f"https://{parsed.netloc}/", "web"

    if scheme == "http" and _is_loopback_host(parsed.hostname):
        # RFC 8252 / Matrix permit HTTP loopback redirects for native clients,
        # while client_uri itself still has to use HTTPS.
        return f"https://{parsed.netloc}/", "native"

    raise ValueError(
        "Dynamic Matrix OAuth registration requires an HTTPS callback or an HTTP loopback callback"
    )


def _build_registration_metadata(
    redirect_uri: str | None,
    grant_types: list[str],
) -> dict[str, object]:
    client_uri, application_type = _registration_client_identity(redirect_uri)
    metadata: dict[str, object] = {
        "client_name": "AstrBot Matrix Client",
        "client_uri": client_uri,
        "grant_types": list(grant_types),
        # AstrBot's dynamically registered client is deliberately public. PKCE
        # protects the authorization-code flow; device grant also has no client
        # authentication secret.
        "token_endpoint_auth_method": "none",
        "application_type": application_type,
    }
    if redirect_uri:
        metadata["redirect_uris"] = [redirect_uri]
        if "authorization_code" in grant_types:
            metadata["response_types"] = ["code"]
    return metadata


class MatrixOAuth2DiscoveryRegistrationMixin:
    async def _register_client(
        self,
        redirect_uri: str | None = None,
        *,
        grant_types: list[str] | None = None,
    ) -> dict[str, str | None]:
        """Dynamically register a public Matrix OAuth client.

        ``redirect_uri`` may be omitted for Matrix v1.18 / MSC4341 device-code
        clients. Authorization-code registrations derive ``client_uri`` from
        the callback host so strict Matrix redirect validation succeeds.
        """
        if not self.registration_endpoint:
            raise Exception(
                "Dynamic client registration not supported by this server. "
                "Please provide a client_id manually."
            )

        try:
            _log("info", f"Registering OAuth2 client with {self.registration_endpoint}")

            requested_grants = list(
                grant_types or ["authorization_code", "refresh_token"]
            )
            registration_data = _build_registration_metadata(
                redirect_uri,
                requested_grants,
            )

            timeout_cfg = aiohttp.ClientTimeout(
                total=self._get_oauth_http_timeout_seconds()
            )
            async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
                async with session.post(
                    self.registration_endpoint,
                    json=registration_data,
                    headers={"Content-Type": "application/json"},
                ) as response:
                    if response.status not in [200, 201]:
                        error_text = await response.text()
                        raise Exception(
                            f"Client registration failed: HTTP {response.status} - {error_text}"
                        )

                    registration_response = await response.json()

                    client_id = registration_response.get("client_id")
                    if not client_id:
                        raise Exception("No client_id in registration response")

                    # We requested token_endpoint_auth_method=none. A secret in
                    # the response is therefore not a credential this public
                    # client should persist or send to the token endpoint.
                    if registration_response.get("client_secret"):
                        _log(
                            "debug",
                            "Ignoring client_secret returned for public OAuth client registration",
                        )

                    _log("info", f"✅ Successfully registered client: {client_id}")

                    return {
                        "client_id": str(client_id),
                        "client_secret": None,
                    }

        except Exception as e:
            _log("error", f"❌ Failed to register OAuth2 client: {e}")
            raise


__all__ = [
    "MatrixOAuth2DiscoveryRegistrationMixin",
    "_build_registration_metadata",
    "_registration_client_identity",
]

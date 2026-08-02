"""Composable OAuth2 discovery and client registration helpers."""

import aiohttp

from ..core import _log  # noqa: F401
from .endpoints import MatrixOAuth2DiscoveryEndpointsMixin
from .metadata import MatrixOAuth2DiscoveryMetadataMixin
from .registration import MatrixOAuth2DiscoveryRegistrationMixin
from .timeout import MatrixOAuth2DiscoveryTimeoutMixin


class MatrixOAuth2Discovery(
    MatrixOAuth2DiscoveryTimeoutMixin,
    MatrixOAuth2DiscoveryMetadataMixin,
    MatrixOAuth2DiscoveryEndpointsMixin,
    MatrixOAuth2DiscoveryRegistrationMixin,
):
    """Mixin for OAuth2 discovery and registration."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MatrixOAuth2Discovery._get_oauth_http_timeout_seconds = (
    MatrixOAuth2DiscoveryTimeoutMixin.__dict__["_get_oauth_http_timeout_seconds"]
)
MatrixOAuth2Discovery._apply_discovered_oauth_metadata = (
    MatrixOAuth2DiscoveryMetadataMixin.__dict__["_apply_discovered_oauth_metadata"]
)
MatrixOAuth2Discovery._discover_oauth_endpoints = (
    MatrixOAuth2DiscoveryEndpointsMixin.__dict__["_discover_oauth_endpoints"]
)
MatrixOAuth2Discovery._register_client = (
    MatrixOAuth2DiscoveryRegistrationMixin.__dict__[  # noqa: E501
        "_register_client"
    ]
)


__all__ = ["MatrixOAuth2Discovery", "aiohttp"]

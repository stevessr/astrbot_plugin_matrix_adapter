"""Composable Matrix capability and registration discovery operations."""

from typing import Any  # noqa: F401

from .capabilities import AuthDiscoveryCapabilitiesMixin
from .registration import AuthDiscoveryRegistrationMixin


class AuthDiscoveryMixin(
    AuthDiscoveryCapabilitiesMixin,
    AuthDiscoveryRegistrationMixin,
):
    """Discover supported client, login, and registration capabilities."""

    pass


# Preserve direct method attributes exposed by the former mixin.
AuthDiscoveryMixin.get_versions = AuthDiscoveryCapabilitiesMixin.__dict__[
    "get_versions"
]
AuthDiscoveryMixin.get_capabilities = AuthDiscoveryCapabilitiesMixin.__dict__[
    "get_capabilities"
]
AuthDiscoveryMixin.get_login_flows = AuthDiscoveryCapabilitiesMixin.__dict__[
    "get_login_flows"
]
AuthDiscoveryMixin.get_register_flows = AuthDiscoveryRegistrationMixin.__dict__[
    "get_register_flows"
]
AuthDiscoveryMixin.register_available = AuthDiscoveryRegistrationMixin.__dict__[
    "register_available"
]
AuthDiscoveryMixin.register_guest = AuthDiscoveryRegistrationMixin.__dict__[
    "register_guest"
]


__all__ = ["Any", "AuthDiscoveryMixin"]

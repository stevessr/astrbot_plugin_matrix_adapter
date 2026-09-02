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


# Preserve direct method attributes exposed by the former mixin. Keep this
# list explicit so capability helpers remain discoverable to callers which
# introspect ``AuthDiscoveryMixin.__dict__`` rather than relying on inheritance.
for _name in (
    "get_versions",
    "get_server_support",
    "get_msc4357_server_advertisement",
    "get_capabilities",
    "is_forget_forced_upon_leave",
    "get_account_moderation_capability",
    "can_change_3pids",
    "can_get_login_token",
    "get_profile_fields_capability",
    "can_set_profile_field",
    "get_login_flows",
    "get_oauth_aware_preferred_sso_flow",
):
    setattr(
        AuthDiscoveryMixin,
        _name,
        AuthDiscoveryCapabilitiesMixin.__dict__[_name],
    )

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

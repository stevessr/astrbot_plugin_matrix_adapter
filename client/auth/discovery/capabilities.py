"""Matrix client and login capability discovery operations."""

import re
from typing import Any

from ....constants import M_PROFILE_FIELDS_CAPABILITY

FORGET_FORCED_UPON_LEAVE_CAPABILITY = "m.forget_forced_upon_leave"
ACCOUNT_MODERATION_CAPABILITY = "m.account_moderation"
THREEPID_CHANGES_CAPABILITY = "m.3pid_changes"


class AuthDiscoveryCapabilitiesMixin:
    """Discover supported Matrix client and login capabilities."""

    async def get_versions(self) -> dict[str, Any]:
        """Get supported Matrix client-server API versions."""
        return await self._request(
            "GET", "/_matrix/client/versions", authenticated=False
        )

    async def get_msc4357_server_advertisement(self) -> bool | None:
        """Read the advisory MSC4357 advertisement used by the dev branch.

        MSC4357 defines no mandatory ``/versions`` feature flag. Some servers
        nevertheless publish ``org.matrix.msc4357`` or its ``.stable`` hint;
        preserve the dev-branch behaviour and treat absence as unknown.
        """
        versions = await self.get_versions()
        unstable = (
            versions.get("unstable_features", {})
            if isinstance(versions, dict)
            else {}
        )
        if not isinstance(unstable, dict):
            return None
        for feature in ("org.matrix.msc4357.stable", "org.matrix.msc4357"):
            value = unstable.get(feature)
            if isinstance(value, bool):
                return value
        return None

    async def get_capabilities(self) -> dict[str, Any]:
        """Get server capabilities."""
        return await self._request("GET", "/_matrix/client/v3/capabilities")

    async def is_forget_forced_upon_leave(self) -> bool:
        """Return the Matrix v1.18 forced-forget capability (MSC4267).

        Missing capability data is deliberately treated as ``False`` as required
        by the stable specification.
        """
        response = await self.get_capabilities()
        capabilities = (
            response.get("capabilities", {}) if isinstance(response, dict) else {}
        )
        capability = capabilities.get(FORGET_FORCED_UPON_LEAVE_CAPABILITY, {})
        return isinstance(capability, dict) and capability.get("enabled") is True

    async def get_account_moderation_capability(self) -> dict[str, bool]:
        """Return Matrix v1.18 / MSC4323 account moderation permissions."""
        response = await self.get_capabilities()
        capabilities = (
            response.get("capabilities", {}) if isinstance(response, dict) else {}
        )
        capability = capabilities.get(ACCOUNT_MODERATION_CAPABILITY, {})
        if not isinstance(capability, dict):
            capability = {}
        return {
            "lock": capability.get("lock") is True,
            "suspend": capability.get("suspend") is True,
        }

    async def can_change_3pids(self) -> bool:
        """Honor ``m.3pid_changes`` as required by OAuth-aware clients.

        Matrix specifies that clients assume 3PID changes are allowed when the
        capability is absent.
        """
        response = await self.get_capabilities()
        capabilities = (
            response.get("capabilities", {}) if isinstance(response, dict) else {}
        )
        capability = capabilities.get(THREEPID_CHANGES_CAPABILITY)
        if capability is None:
            return True
        return isinstance(capability, dict) and capability.get("enabled") is True

    async def get_profile_fields_capability(self) -> dict[str, Any] | None:
        """Return the stable Matrix v1.16 ``m.profile_fields`` capability.

        ``None`` means the homeserver omitted the capability. Matrix v1.16+
        permits clients to infer custom profile fields are supported in that
        case, which ``can_set_profile_field`` handles using ``/versions``.
        """
        response = await self.get_capabilities()
        capabilities = (
            response.get("capabilities", {}) if isinstance(response, dict) else {}
        )
        capability = capabilities.get(M_PROFILE_FIELDS_CAPABILITY)
        return dict(capability) if isinstance(capability, dict) else None

    @staticmethod
    def _versions_include_v116_or_later(response: dict[str, Any]) -> bool:
        versions = response.get("versions", []) if isinstance(response, dict) else []
        if not isinstance(versions, list):
            return False
        for version in versions:
            if not isinstance(version, str):
                continue
            match = re.fullmatch(r"v(\d+)\.(\d+)", version.strip())
            if not match:
                continue
            major, minor = (int(match.group(1)), int(match.group(2)))
            if major > 1 or (major == 1 and minor >= 16):
                return True
        return False

    async def can_set_profile_field(self, key_name: str) -> bool | None:
        """Check whether the homeserver permits modifying a profile field.

        Returns ``None`` only when the server omits ``m.profile_fields`` and
        does not advertise Matrix v1.16+, leaving support genuinely unknown.
        """
        if not isinstance(key_name, str) or not key_name.strip():
            raise ValueError("key_name must be a non-empty string")
        key_name = key_name.strip()

        capability = await self.get_profile_fields_capability()
        if capability is None:
            versions = await self.get_versions()
            return True if self._versions_include_v116_or_later(versions) else None
        if capability.get("enabled") is not True:
            return False

        allowed = capability.get("allowed")
        if isinstance(allowed, list):
            return key_name in allowed

        disallowed = capability.get("disallowed")
        if isinstance(disallowed, list):
            return key_name not in disallowed
        return True

    async def get_login_flows(self) -> dict[str, Any]:
        """Get supported login flows from the server."""
        return await self._request(
            "GET", "/_matrix/client/v3/login", authenticated=False
        )

    async def get_oauth_aware_preferred_sso_flow(self) -> dict[str, Any] | None:
        """Return the stable MSC3824 preferred SSO flow, if advertised."""
        response = await self.get_login_flows()
        flows = response.get("flows", []) if isinstance(response, dict) else []
        if not isinstance(flows, list):
            return None
        for flow in flows:
            if (
                isinstance(flow, dict)
                and flow.get("type") == "m.login.sso"
                and flow.get("oauth_aware_preferred") is True
            ):
                return flow
        return None

"""SSO login flow discovery."""

from .....constants import LOGIN_TYPE_SSO
from ....oauth2.core import _log


class MatrixSSOLoginFlowsMixin:
    """Discover and validate SSO login flows."""

    def _discover_sso_login_flow(self, flows_response: dict) -> dict:
        """Return the SSO flow, raising when the homeserver lacks SSO."""
        flows = flows_response.get("flows", [])

        sso_flow = None
        for flow in flows:
            if flow.get("type") == LOGIN_TYPE_SSO:
                sso_flow = flow
                break

        if not sso_flow:
            raise RuntimeError("SSO login not supported by this homeserver.")

        idps = sso_flow.get("identity_providers", []) or []
        if idps:
            idp_names = ", ".join(
                [f"{i.get('name', i.get('id', 'unknown'))}" for i in idps]
            )
            _log("info", f"SSO identity providers: {idp_names}")
        return sso_flow


__all__ = ["MatrixSSOLoginFlowsMixin"]

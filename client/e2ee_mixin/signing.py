"""Matrix cross-signing upload and key-change operations."""

from typing import Any


class E2EESigningMixin:
    """Upload signatures and cross-signing keys."""

    async def upload_signatures(self, signatures: dict[str, Any]) -> dict[str, Any]:
        """
        Upload signatures for device and cross-signing keys

        Args:
            signatures: Signed objects dict, keyed by user_id

        Returns:
            Response with failures
        """
        endpoint = "/_matrix/client/v3/keys/signatures/upload"
        return await self._request("POST", endpoint, data=signatures)

    async def upload_signing_keys(
        self,
        master_key: dict[str, Any] | None = None,
        self_signing_key: dict[str, Any] | None = None,
        user_signing_key: dict[str, Any] | None = None,
        auth: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Upload cross-signing keys

        Args:
            master_key: Master signing key
            self_signing_key: Self-signing key
            user_signing_key: User-signing key
            auth: Optional UIA auth dict

        Returns:
            Response data
        """
        endpoint = "/_matrix/client/v3/keys/device_signing/upload"
        data: dict[str, Any] = {}
        if master_key:
            data["master_key"] = master_key
        if self_signing_key:
            data["self_signing_key"] = self_signing_key
        if user_signing_key:
            data["user_signing_key"] = user_signing_key
        if auth:
            data["auth"] = auth
        return await self._request("POST", endpoint, data=data)

    async def get_keys_changes(self, from_token: str, to_token: str) -> dict[str, Any]:
        """
        Get key changes between two sync tokens

        Args:
            from_token: Start token
            to_token: End token

        Returns:
            Keys changes response
        """
        endpoint = "/_matrix/client/v3/keys/changes"
        params = {"from": from_token, "to": to_token}
        return await self._request("GET", endpoint, params=params)

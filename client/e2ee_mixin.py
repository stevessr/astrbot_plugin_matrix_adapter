"""
Matrix HTTP Client - E2EE Mixin
Provides end-to-end encryption related methods
"""

from typing import Any

from astrbot.api import logger

from ..constants import KEY_QUERY_TIMEOUT_MS_10000


class E2EEMixin:
    """End-to-end encryption methods for Matrix client"""

    async def upload_keys(
        self,
        device_keys: dict[str, Any] | None = None,
        one_time_keys: dict[str, Any] | None = None,
        fallback_keys: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Upload device keys, one-time keys, and fallback keys

        Args:
            device_keys: Device identity keys
            one_time_keys: One-time pre-keys
            fallback_keys: Fallback keys

        Returns:
            Response with one_time_key_counts
        """
        endpoint = "/_matrix/client/v3/keys/upload"
        data: dict[str, Any] = {}

        if device_keys:
            data["device_keys"] = device_keys
            # 记录设备密钥信息用于调试
            algorithms = device_keys.get("algorithms", [])
            device_id = device_keys.get("device_id", "unknown")
            logger.info(f"上传设备密钥：device_id={device_id}, algorithms={algorithms}")

        if one_time_keys:
            otk_count = len(one_time_keys)
            logger.debug(f"上传 {otk_count} 个一次性密钥")
            data["one_time_keys"] = one_time_keys
        if fallback_keys:
            logger.debug("上传备用密钥")
            data["fallback_keys"] = fallback_keys

        return await self._request("POST", endpoint, data=data)

    async def query_keys(
        self,
        device_keys: dict[str, list[str]],
        timeout: int = KEY_QUERY_TIMEOUT_MS_10000,
    ) -> dict[str, Any]:
        """
        Query device keys for users

        Args:
            device_keys: Dict of user_id -> list of device_ids (empty list = all devices)
            timeout: Timeout in milliseconds

        Returns:
            Response with device_keys
        """
        endpoint = "/_matrix/client/v3/keys/query"
        data = {"device_keys": device_keys, "timeout": timeout}
        return await self._request("POST", endpoint, data=data)

    async def claim_keys(
        self,
        one_time_keys: dict[str, dict[str, str]],
        timeout: int = 10000,
    ) -> dict[str, Any]:
        """
        Claim one-time keys from other users' devices

        Args:
            one_time_keys: Dict of user_id -> {device_id -> algorithm}
            timeout: Timeout in milliseconds

        Returns:
            Response with claimed one_time_keys
        """
        endpoint = "/_matrix/client/v3/keys/claim"
        data = {"one_time_keys": one_time_keys, "timeout": timeout}
        return await self._request("POST", endpoint, data=data)

    async def get_keys_changes(
        self, from_token: str, to_token: str
    ) -> dict[str, Any]:
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

"""
Matrix HTTP Client - Push/Notifications Mixin
Provides push rules and notifications methods
"""

from typing import Any


class PushMixin:
    """Push rules and notifications methods for Matrix client"""

    async def get_push_rules(self) -> dict[str, Any]:
        """
        Get all push rules

        Returns:
            Push rules response
        """
        return await self._request("GET", "/_matrix/client/v3/pushrules")

    async def get_push_rule(
        self, scope: str, kind: str, rule_id: str
    ) -> dict[str, Any]:
        """
        Get a specific push rule
        """
        endpoint = f"/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}"
        return await self._request("GET", endpoint)

    async def delete_push_rule(
        self, scope: str, kind: str, rule_id: str
    ) -> dict[str, Any]:
        """
        Delete a push rule
        """
        endpoint = f"/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}"
        return await self._request("DELETE", endpoint)

    async def set_push_rule(
        self,
        scope: str,
        kind: str,
        rule_id: str,
        rule: dict[str, Any],
        before: str | None = None,
        after: str | None = None,
    ) -> dict[str, Any]:
        """
        Create or update a push rule
        """
        endpoint = f"/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}"
        params: dict[str, Any] = {}
        if before:
            params["before"] = before
        if after:
            params["after"] = after
        return await self._request("PUT", endpoint, data=rule, params=params)

    async def get_push_rule_actions(
        self, scope: str, kind: str, rule_id: str
    ) -> dict[str, Any]:
        """
        Get actions for a push rule
        """
        endpoint = f"/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/actions"
        return await self._request("GET", endpoint)

    async def set_push_rule_actions(
        self, scope: str, kind: str, rule_id: str, actions: list[Any]
    ) -> dict[str, Any]:
        """
        Set actions for a push rule
        """
        endpoint = f"/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/actions"
        return await self._request("PUT", endpoint, data={"actions": actions})

    async def get_push_rule_enabled(
        self, scope: str, kind: str, rule_id: str
    ) -> dict[str, Any]:
        """
        Get enabled state for a push rule
        """
        endpoint = f"/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/enabled"
        return await self._request("GET", endpoint)

    async def set_push_rule_enabled(
        self, scope: str, kind: str, rule_id: str, enabled: bool
    ) -> dict[str, Any]:
        """
        Set enabled state for a push rule
        """
        endpoint = f"/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/enabled"
        return await self._request("PUT", endpoint, data={"enabled": enabled})

    async def get_pushers(self) -> dict[str, Any]:
        """
        Get registered pushers
        """
        return await self._request("GET", "/_matrix/client/v3/pushers")

    async def set_pusher(self, pusher: dict[str, Any]) -> dict[str, Any]:
        """
        Create or update a pusher
        """
        return await self._request("POST", "/_matrix/client/v3/pushers/set", data=pusher)

    async def get_notifications(
        self, from_token: str, limit: int | None = None, only: str | None = None
    ) -> dict[str, Any]:
        """
        Get notifications
        """
        params: dict[str, Any] = {"from": from_token}
        if limit is not None:
            params["limit"] = limit
        if only:
            params["only"] = only
        return await self._request("GET", "/_matrix/client/v3/notifications", params=params)

"""Matrix push-rule mutation operations."""

from typing import Any

from ...path_utils import quote_path_segment


class PushRuleUpdateMixin:
    """Create, delete, and update Matrix push rules."""

    async def delete_push_rule(
        self, scope: str, kind: str, rule_id: str
    ) -> dict[str, Any]:
        """
        Delete a push rule
        """
        scope_path = quote_path_segment(scope)
        kind_path = quote_path_segment(kind)
        rule = quote_path_segment(rule_id)
        endpoint = f"/_matrix/client/v3/pushrules/{scope_path}/{kind_path}/{rule}"
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
        scope_path = quote_path_segment(scope)
        kind_path = quote_path_segment(kind)
        rule = quote_path_segment(rule_id)
        endpoint = f"/_matrix/client/v3/pushrules/{scope_path}/{kind_path}/{rule}"
        params: dict[str, Any] = {}
        if before:
            params["before"] = before
        if after:
            params["after"] = after
        return await self._request("PUT", endpoint, data=rule, params=params)

    async def set_push_rule_actions(
        self, scope: str, kind: str, rule_id: str, actions: list[Any]
    ) -> dict[str, Any]:
        """
        Set actions for a push rule
        """
        scope_path = quote_path_segment(scope)
        kind_path = quote_path_segment(kind)
        rule = quote_path_segment(rule_id)
        endpoint = (
            f"/_matrix/client/v3/pushrules/{scope_path}/{kind_path}/{rule}/actions"
        )
        return await self._request("PUT", endpoint, data={"actions": actions})

    async def set_push_rule_enabled(
        self, scope: str, kind: str, rule_id: str, enabled: bool
    ) -> dict[str, Any]:
        """
        Set enabled state for a push rule
        """
        scope_path = quote_path_segment(scope)
        kind_path = quote_path_segment(kind)
        rule = quote_path_segment(rule_id)
        endpoint = (
            f"/_matrix/client/v3/pushrules/{scope_path}/{kind_path}/{rule}/enabled"
        )
        return await self._request("PUT", endpoint, data={"enabled": enabled})


__all__ = ["PushRuleUpdateMixin"]

"""Matrix push-rule query operations."""

from typing import Any

from ...path_utils import quote_path_segment

SUPPRESS_EDITS_RULE_ID = "m.rule.suppress_edits"


class PushRuleQueryMixin:
    """Inspect Matrix push rules."""

    async def get_push_rules(self) -> dict[str, Any]:
        """Get all push rules."""
        return await self._request("GET", "/_matrix/client/v3/pushrules")

    async def get_push_rule(
        self, scope: str, kind: str, rule_id: str
    ) -> dict[str, Any]:
        """Get a specific push rule."""
        scope_path = quote_path_segment(scope)
        kind_path = quote_path_segment(kind)
        rule = quote_path_segment(rule_id)
        endpoint = f"/_matrix/client/v3/pushrules/{scope_path}/{kind_path}/{rule}"
        return await self._request("GET", endpoint)

    async def get_push_rule_actions(
        self, scope: str, kind: str, rule_id: str
    ) -> dict[str, Any]:
        """Get actions for a push rule."""
        scope_path = quote_path_segment(scope)
        kind_path = quote_path_segment(kind)
        rule = quote_path_segment(rule_id)
        endpoint = (
            f"/_matrix/client/v3/pushrules/{scope_path}/{kind_path}/{rule}/actions"
        )
        return await self._request("GET", endpoint)

    async def get_push_rule_enabled(
        self, scope: str, kind: str, rule_id: str
    ) -> dict[str, Any]:
        """Get enabled state for a push rule."""
        scope_path = quote_path_segment(scope)
        kind_path = quote_path_segment(kind)
        rule = quote_path_segment(rule_id)
        endpoint = (
            f"/_matrix/client/v3/pushrules/{scope_path}/{kind_path}/{rule}/enabled"
        )
        return await self._request("GET", endpoint)

    async def is_suppress_edits_push_rule_enabled(self) -> bool:
        """Return whether the Matrix v1.9 / MSC3958 default edit-suppression rule is enabled.

        ``m.rule.suppress_edits`` is a global override rule supplied by the
        homeserver. Querying the dedicated ``/enabled`` endpoint avoids
        duplicating the full Matrix push-rule evaluator inside the adapter.
        """
        response = await self.get_push_rule_enabled(
            "global", "override", SUPPRESS_EDITS_RULE_ID
        )
        return isinstance(response, dict) and response.get("enabled") is True


__all__ = ["PushRuleQueryMixin", "SUPPRESS_EDITS_RULE_ID"]

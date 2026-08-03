"""Reaction key resolution and resolver registry helpers."""


class MatrixUtilsReactionKeysMixin:
    """Resolve reaction keys and manage external resolvers."""

    @staticmethod
    async def resolve_reaction_key(
        reaction: str,
        *,
        context=None,
        room_id: str = "",
        platform_id: str = "",
        event=None,
    ) -> str:
        """Resolve a reaction key (Unicode emoji / shortcode / mxc://).

        External plugins can inject shortcode→mxc resolvers via
        ``register_reaction_key_resolver``.
        """
        from ...reaction_helpers import resolve_reaction_key as _resolve_reaction_key

        return await _resolve_reaction_key(
            reaction,
            context=context,
            room_id=room_id,
            platform_id=platform_id,
            event=event,
        )

    @staticmethod
    def register_reaction_key_resolver(resolver) -> bool:
        """Register a reaction-key resolver used by ``resolve_reaction_key``."""
        from ...reaction_helpers import register_reaction_key_resolver

        return register_reaction_key_resolver(resolver)

    @staticmethod
    def unregister_reaction_key_resolver(resolver) -> bool:
        """Unregister a reaction-key resolver."""
        from ...reaction_helpers import unregister_reaction_key_resolver

        return unregister_reaction_key_resolver(resolver)

    @staticmethod
    def list_reaction_key_resolvers() -> list:
        """Return currently registered reaction-key resolvers."""
        from ...reaction_helpers import list_reaction_key_resolvers

        return list_reaction_key_resolvers()

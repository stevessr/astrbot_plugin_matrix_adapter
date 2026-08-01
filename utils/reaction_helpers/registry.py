"""Reaction-key resolver registry."""

from collections.abc import Awaitable, Callable

ReactionKeyResolver = Callable[..., str | None | Awaitable[str | None]]
_REACTION_KEY_RESOLVERS: list[ReactionKeyResolver] = []


def register_reaction_key_resolver(resolver: ReactionKeyResolver) -> bool:
    """Register a reaction-key resolver. Duplicates are ignored."""
    if resolver is None or not callable(resolver):
        return False
    if resolver in _REACTION_KEY_RESOLVERS:
        return False
    _REACTION_KEY_RESOLVERS.append(resolver)
    return True


def unregister_reaction_key_resolver(resolver: ReactionKeyResolver) -> bool:
    """Unregister a previously registered reaction-key resolver."""
    try:
        _REACTION_KEY_RESOLVERS.remove(resolver)
    except ValueError:
        return False
    return True


def list_reaction_key_resolvers() -> list[ReactionKeyResolver]:
    """Return a copy of registered reaction-key resolvers."""
    return list(_REACTION_KEY_RESOLVERS)


def clear_reaction_key_resolvers() -> None:
    """Remove all registered reaction-key resolvers (primarily for tests)."""
    _REACTION_KEY_RESOLVERS.clear()

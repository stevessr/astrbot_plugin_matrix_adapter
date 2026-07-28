# Matrix Adapter Plugin for AstrBot

# Public exports for other AstrBot plugins.
from .sticker import Sticker, StickerInfo, StickerStorage
from .utils import (
    MatrixUtils,
    clear_reaction_key_resolvers,
    register_reaction_key_resolver,
    resolve_reaction_key,
    unregister_reaction_key_resolver,
)

__all__ = [
    "MatrixUtils",
    "Sticker",
    "StickerInfo",
    "StickerStorage",
    "clear_reaction_key_resolvers",
    "register_reaction_key_resolver",
    "resolve_reaction_key",
    "unregister_reaction_key_resolver",
]

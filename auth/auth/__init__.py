"""Layered Matrix authentication coordinator."""

from ..login import MatrixAuthLogin
from ..store import MatrixAuthStore
from .dispatch import MatrixAuthDispatchMixin
from .identity import MatrixAuthIdentityMixin


class MatrixAuth(
    MatrixAuthStore,
    MatrixAuthLogin,
    MatrixAuthIdentityMixin,
    MatrixAuthDispatchMixin,
):
    """Compose authentication storage, flows, identity, and dispatch."""

    pass


__all__ = [
    "MatrixAuth",
    "MatrixAuthDispatchMixin",
    "MatrixAuthIdentityMixin",
]

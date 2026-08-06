"""Adapter client and runtime state construction."""

from __future__ import annotations

from ....client import MatrixHTTPClient
from ....config.matrix import MatrixConfig
from ...state import MatrixRuntimeState


def _build_adapter_client(
    matrix_config: MatrixConfig,
) -> tuple[MatrixHTTPClient, MatrixRuntimeState]:
    """Construct the HTTP client and its runtime state."""
    client = MatrixHTTPClient(homeserver=matrix_config.homeserver)
    runtime_state = MatrixRuntimeState()
    client.runtime_state = runtime_state
    return client, runtime_state


__all__ = ["_build_adapter_client"]

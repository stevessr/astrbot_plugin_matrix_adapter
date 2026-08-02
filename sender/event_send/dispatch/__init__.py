"""Composable message-chain dispatch implementation."""

from .context import SendContext, build_send_context
from .core import send_with_client_impl
from .segments import send_segments

__all__ = [
    "SendContext",
    "build_send_context",
    "send_segments",
    "send_with_client_impl",
]

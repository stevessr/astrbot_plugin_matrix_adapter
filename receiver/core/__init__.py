"""Layered Matrix receiver core."""

# Kept importable: tests patch receiver.core.get_plugin_config to stub
# plugin config. Receiver mixins import it directly from ..config.plugin.
from ...config.plugin import get_plugin_config  # noqa: F401
from .receiver import MatrixReceiver

__all__ = ["MatrixReceiver", "get_plugin_config"]

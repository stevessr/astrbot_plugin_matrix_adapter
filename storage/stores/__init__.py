"""Persistent stores for users, rooms, devices, and outbound events."""

from importlib import import_module

__all__ = [
    "MatrixDeviceManager",
    "MatrixOutboundTracker",
    "MatrixRoomMemberStore",
    "MatrixUserStore",
]

_EXPORTS = {
    "MatrixDeviceManager": (".device", "MatrixDeviceManager"),
    "MatrixOutboundTracker": (".outbound", "MatrixOutboundTracker"),
    "MatrixRoomMemberStore": (".rooms", "MatrixRoomMemberStore"),
    "MatrixUserStore": (".users", "MatrixUserStore"),
}


def __getattr__(name: str):
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    return getattr(import_module(module_name, __name__), attribute_name)

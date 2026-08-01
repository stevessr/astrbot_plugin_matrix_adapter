"""Adapter lifecycle, message, and send mixins."""

from importlib import import_module

__all__ = [
    "MatrixAdapterMessageMixin",
    "MatrixAdapterRuntimeMixin",
    "MatrixAdapterSendMixin",
    "MatrixRuntimeState",
]

_EXPORTS = {
    "MatrixAdapterMessageMixin": (".message", "MatrixAdapterMessageMixin"),
    "MatrixAdapterRuntimeMixin": (".runtime", "MatrixAdapterRuntimeMixin"),
    "MatrixAdapterSendMixin": (".send", "MatrixAdapterSendMixin"),
    "MatrixRuntimeState": (".state", "MatrixRuntimeState"),
}


def __getattr__(name: str):
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    return getattr(import_module(module_name, __name__), attribute_name)

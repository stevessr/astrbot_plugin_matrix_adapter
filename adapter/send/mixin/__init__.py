"""Session-oriented Matrix adapter send operations."""

from .config import _get_plugin_config
from .context import MatrixAdapterSendContextMixin
from .core import MatrixAdapterSendCoreMixin
from .delivery import MatrixAdapterSendDeliveryMixin
from .typing import MatrixAdapterSendTypingMixin


class MatrixAdapterSendMixin(MatrixAdapterSendCoreMixin):
    """Session-oriented send operations."""

    pass


# Preserve direct method attributes expected by parent mixins.
for _mixin in (
    MatrixAdapterSendCoreMixin,
    MatrixAdapterSendContextMixin,
    MatrixAdapterSendDeliveryMixin,
    MatrixAdapterSendTypingMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if _method_name.startswith("__"):
            continue
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixAdapterSendMixin, _method_name, _method)


__all__ = ["MatrixAdapterSendMixin", "_get_plugin_config"]

"""E2EE manager startup orchestration."""

from .components import E2EEManagerCoreInitializationStartupComponentsMixin
from .core import E2EEManagerCoreInitializationStartupCoreMixin
from .trust import E2EEManagerCoreInitializationStartupTrustMixin


class E2EEManagerCoreInitializationStartupMixin(
    E2EEManagerCoreInitializationStartupCoreMixin,
    E2EEManagerCoreInitializationStartupComponentsMixin,
    E2EEManagerCoreInitializationStartupTrustMixin,
):
    """初始化 E2EE 组件。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    E2EEManagerCoreInitializationStartupCoreMixin,
    E2EEManagerCoreInitializationStartupComponentsMixin,
    E2EEManagerCoreInitializationStartupTrustMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerCoreInitializationStartupMixin, _name, _method)

__all__ = ["E2EEManagerCoreInitializationStartupMixin"]

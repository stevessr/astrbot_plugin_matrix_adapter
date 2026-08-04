"""E2EE manager construction."""

from .core import E2EEManagerCoreInitializationConstructorCoreMixin
from .state import E2EEManagerCoreInitializationConstructorStateMixin
from .storage import E2EEManagerCoreInitializationConstructorStorageMixin


class E2EEManagerCoreInitializationConstructorMixin(
    E2EEManagerCoreInitializationConstructorCoreMixin,
    E2EEManagerCoreInitializationConstructorStorageMixin,
    E2EEManagerCoreInitializationConstructorStateMixin,
):
    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    E2EEManagerCoreInitializationConstructorCoreMixin,
    E2EEManagerCoreInitializationConstructorStorageMixin,
    E2EEManagerCoreInitializationConstructorStateMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerCoreInitializationConstructorMixin, _name, _method)

__all__ = ["E2EEManagerCoreInitializationConstructorMixin"]

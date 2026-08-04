"""Cross-signing initialization lifecycle flow."""

from .complete import CrossSigningCoreFlowCompleteMixin
from .core import CrossSigningCoreFlowCoreMixin
from .restore import CrossSigningCoreFlowRestoreMixin


class CrossSigningCoreFlowMixin(
    CrossSigningCoreFlowCoreMixin,
    CrossSigningCoreFlowRestoreMixin,
    CrossSigningCoreFlowCompleteMixin,
):
    """Drive the cross-signing initialization state machine."""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    CrossSigningCoreFlowCoreMixin,
    CrossSigningCoreFlowRestoreMixin,
    CrossSigningCoreFlowCompleteMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(CrossSigningCoreFlowMixin, _name, _method)

__all__ = ["CrossSigningCoreFlowMixin"]

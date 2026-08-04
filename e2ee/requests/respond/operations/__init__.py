"""Room-key request response operations, split by responsibility.

Public symbols re-exported for backward compatibility.
"""

from .core import E2EEManagerRequestsRespondCoreMixin
from .export import E2EEManagerRequestsRespondExportMixin
from .forward import E2EEManagerRequestsRespondForwardMixin
from .provenance import E2EEManagerRequestsRespondProvenanceMixin
from .verify import E2EEManagerRequestsRespondVerifyMixin


class E2EEManagerRequestsRespondOperationsMixin(
    E2EEManagerRequestsRespondCoreMixin,
    E2EEManagerRequestsRespondVerifyMixin,
    E2EEManagerRequestsRespondExportMixin,
    E2EEManagerRequestsRespondProvenanceMixin,
    E2EEManagerRequestsRespondForwardMixin,
):
    """Respond to room-key requests from verified devices."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerRequestsRespondCoreMixin,
    E2EEManagerRequestsRespondVerifyMixin,
    E2EEManagerRequestsRespondExportMixin,
    E2EEManagerRequestsRespondProvenanceMixin,
    E2EEManagerRequestsRespondForwardMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerRequestsRespondOperationsMixin, _method_name, _method)


__all__ = [
    "E2EEManagerRequestsRespondOperationsMixin",
    "E2EEManagerRequestsRespondCoreMixin",
    "E2EEManagerRequestsRespondVerifyMixin",
    "E2EEManagerRequestsRespondExportMixin",
    "E2EEManagerRequestsRespondProvenanceMixin",
    "E2EEManagerRequestsRespondForwardMixin",
]

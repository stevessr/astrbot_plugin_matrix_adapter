"""Requester verification for room-key requests."""

from .core import E2EEManagerRequestsRespondVerifyOrchestratorMixin
from .identity import E2EEManagerRequestsRespondIdentityMixin


class E2EEManagerRequestsRespondVerifyMixin(
    E2EEManagerRequestsRespondVerifyOrchestratorMixin,
    E2EEManagerRequestsRespondIdentityMixin,
):
    """Verify a requesting device and load its identity keys."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerRequestsRespondVerifyOrchestratorMixin,
    E2EEManagerRequestsRespondIdentityMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerRequestsRespondVerifyMixin, _method_name, _method)


__all__ = [
    "E2EEManagerRequestsRespondIdentityMixin",
    "E2EEManagerRequestsRespondVerifyMixin",
    "E2EEManagerRequestsRespondVerifyOrchestratorMixin",
]

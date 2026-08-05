"""Handle incoming secret requests."""

from .core import E2EEManagerSecretsRequestOrchestratorMixin
from .guard import E2EEManagerSecretsRequestGuardMixin
from .parse import E2EEManagerSecretsRequestParseMixin
from .share import E2EEManagerSecretsRequestShareMixin
from .verify import E2EEManagerSecretsRequestVerifyMixin


class E2EEManagerSecretsRequestCoreMixin(
    E2EEManagerSecretsRequestOrchestratorMixin,
    E2EEManagerSecretsRequestGuardMixin,
    E2EEManagerSecretsRequestParseMixin,
    E2EEManagerSecretsRequestVerifyMixin,
    E2EEManagerSecretsRequestShareMixin,
):
    """处理设备间秘密共享请求。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerSecretsRequestOrchestratorMixin,
    E2EEManagerSecretsRequestGuardMixin,
    E2EEManagerSecretsRequestParseMixin,
    E2EEManagerSecretsRequestVerifyMixin,
    E2EEManagerSecretsRequestShareMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerSecretsRequestCoreMixin, _method_name, _method)


__all__ = ["E2EEManagerSecretsRequestCoreMixin"]

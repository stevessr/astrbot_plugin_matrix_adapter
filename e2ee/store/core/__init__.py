"""Core construction and shared state for the crypto store."""

from .backend import CryptoStoreCoreBackendMixin
from .caches import CryptoStoreCoreCachesMixin
from .constants import CryptoStoreCoreConstantsMixin
from .core import CryptoStoreCoreOrchestratorMixin
from .identity import CryptoStoreCoreIdentityMixin
from .persist import CryptoStoreCorePersistMixin


class CryptoStoreCoreMixin(
    CryptoStoreCoreOrchestratorMixin,
    CryptoStoreCoreConstantsMixin,
    CryptoStoreCoreBackendMixin,
    CryptoStoreCorePersistMixin,
    CryptoStoreCoreCachesMixin,
    CryptoStoreCoreIdentityMixin,
):
    """E2EE 加密状态存储"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    CryptoStoreCoreOrchestratorMixin,
    CryptoStoreCoreBackendMixin,
    CryptoStoreCorePersistMixin,
    CryptoStoreCoreCachesMixin,
    CryptoStoreCoreIdentityMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(CryptoStoreCoreMixin, _method_name, _method)


__all__ = [
    "CryptoStoreCoreBackendMixin",
    "CryptoStoreCoreCachesMixin",
    "CryptoStoreCoreConstantsMixin",
    "CryptoStoreCoreIdentityMixin",
    "CryptoStoreCoreMixin",
    "CryptoStoreCoreOrchestratorMixin",
    "CryptoStoreCorePersistMixin",
]

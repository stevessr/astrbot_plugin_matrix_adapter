from .core import CryptoStoreCoreMixin
from .persist import CryptoStorePersistMixin
from .sessions import CryptoStoreSessionsMixin


class CryptoStore(
    CryptoStoreCoreMixin,
    CryptoStorePersistMixin,
    CryptoStoreSessionsMixin,
):
    """Combined crypto store."""

    pass


__all__ = [
    "CryptoStore",
    "CryptoStoreCoreMixin",
    "CryptoStorePersistMixin",
    "CryptoStoreSessionsMixin",
]

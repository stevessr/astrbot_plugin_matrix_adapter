from .persist import CryptoStorePersistMixin
from .sessions import CryptoStoreSessionsMixin


class CryptoStore(
    CryptoStorePersistMixin,
    CryptoStoreSessionsMixin,
):
    """Combined mixin."""

    pass

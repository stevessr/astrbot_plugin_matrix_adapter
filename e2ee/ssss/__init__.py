from .crypto import KeyBackupSSSSMixinCrypto
from .storage import KeyBackupSSSSStorageMixin


class KeyBackupSSSSMixin(
    KeyBackupSSSSStorageMixin,
    KeyBackupSSSSMixinCrypto,
):
    """Combined mixin."""

    pass

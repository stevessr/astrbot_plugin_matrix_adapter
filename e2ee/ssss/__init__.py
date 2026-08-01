from .storage import KeyBackupSSSSStorageMixin
from .crypto import KeyBackupSSSSMixinCrypto


class KeyBackupSSSSMixin(
    KeyBackupSSSSStorageMixin,
    KeyBackupSSSSMixinCrypto,
):
    """Combined mixin."""
    pass

from .crypto import KeyBackupBackupCryptoMixin
from .restore import KeyBackupBackupRestoreMixin
from .upload import KeyBackupBackupUploadMixin


class KeyBackupBackupMixin(
    KeyBackupBackupCryptoMixin,
    KeyBackupBackupRestoreMixin,
    KeyBackupBackupUploadMixin,
):
    """Combined mixin."""

    pass

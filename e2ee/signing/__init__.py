from .crypto import CrossSigningCryptoMixin
from .restore import CrossSigningRestoreMixin
from .upload import CrossSigningUploadMixin
from .sign import CrossSigningSignMixin


class CrossSigning(
    CrossSigningCryptoMixin,
    CrossSigningRestoreMixin,
    CrossSigningUploadMixin,
    CrossSigningSignMixin,
):
    """Combined mixin."""
    pass

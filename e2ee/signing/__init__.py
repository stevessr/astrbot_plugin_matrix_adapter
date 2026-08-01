from .crypto import CrossSigningCryptoMixin
from .restore import CrossSigningRestoreMixin
from .sign import CrossSigningSignMixin
from .upload import CrossSigningUploadMixin


class CrossSigning(
    CrossSigningCryptoMixin,
    CrossSigningRestoreMixin,
    CrossSigningUploadMixin,
    CrossSigningSignMixin,
):
    """Combined mixin."""

    pass

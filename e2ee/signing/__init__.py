from .core import CrossSigningCoreMixin
from .crypto import CrossSigningCryptoMixin
from .restore import CrossSigningRestoreMixin
from .sign import CrossSigningSignMixin
from .upload import CrossSigningUploadMixin


class CrossSigning(
    CrossSigningCoreMixin,
    CrossSigningCryptoMixin,
    CrossSigningRestoreMixin,
    CrossSigningUploadMixin,
    CrossSigningSignMixin,
):
    """Combined cross-signing manager."""

    pass


__all__ = [
    "CrossSigning",
    "CrossSigningCoreMixin",
    "CrossSigningCryptoMixin",
    "CrossSigningRestoreMixin",
    "CrossSigningUploadMixin",
    "CrossSigningSignMixin",
]

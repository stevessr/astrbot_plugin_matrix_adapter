"""Cross-signing upload readiness guard."""

from ....backup.crypto_utils import CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE
from ..compat import resolve_upload_symbol


class CrossSigningUploadGuardMixin:
    """Check cross-signing upload readiness."""

    def _cross_signing_upload_ready(self) -> bool:
        """Return whether the crypto backend is available."""
        return bool(
            resolve_upload_symbol("CRYPTO_AVAILABLE", _DEFAULT_CRYPTO_AVAILABLE)
        )


__all__ = ["CrossSigningUploadGuardMixin"]

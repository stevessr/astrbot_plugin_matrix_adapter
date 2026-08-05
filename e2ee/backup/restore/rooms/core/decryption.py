"""PkDecryption helper construction."""

from astrbot.api import logger

from ....crypto_utils import (
    VODOZEMAC_PK_AVAILABLE as _DEFAULT_VODOZEMAC_PK_AVAILABLE,
)
from ....crypto_utils import (
    Curve25519SecretKey as _DEFAULT_CURVE25519_SECRET_KEY,
)
from ....crypto_utils import (
    PkDecryption as _DEFAULT_PK_DECRYPTION,
)
from ...compat import resolve_restore_symbol


class KeyBackupRoomKeysRestoreDecryptionMixin:
    """Build the vodozemac PkDecryption object when available."""

    def _build_pk_decryption(self, key_bytes: bytes):
        _pk_decryption = None
        if resolve_restore_symbol(
            "VODOZEMAC_PK_AVAILABLE", _DEFAULT_VODOZEMAC_PK_AVAILABLE
        ):
            try:
                # key_bytes 需要转换为 Curve25519SecretKey 对象
                secret_key_cls = resolve_restore_symbol(
                    "Curve25519SecretKey", _DEFAULT_CURVE25519_SECRET_KEY
                )
                pk_decryption_cls = resolve_restore_symbol(
                    "PkDecryption", _DEFAULT_PK_DECRYPTION
                )
                secret_key = secret_key_cls.from_bytes(key_bytes)
                _pk_decryption = pk_decryption_cls.from_key(secret_key)
                logger.debug("使用 vodozemac PkDecryption 解密备份")
            except Exception as e:
                logger.warning(f"创建 PkDecryption 失败：{e}")
        return _pk_decryption


__all__ = ["KeyBackupRoomKeysRestoreDecryptionMixin"]

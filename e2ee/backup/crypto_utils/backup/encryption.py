"""Matrix key-backup encryption helpers."""

import base64
import hashlib
import hmac

from .. import (
    AES_BLOCK_SIZE_16,
    CRYPTO_KEY_SIZE_32,
    HKDF_KEY_MATERIAL_LEN,
    HKDF_MEGOLM_BACKUP_INFO,
    MAC_TRUNCATED_BYTES_8,
)
from .. import (
    CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE,
)
from .. import (
    VODOZEMAC_PK_AVAILABLE as _DEFAULT_VODOZEMAC_PK_AVAILABLE,
)
from .. import (
    Curve25519PublicKey as _DEFAULT_CURVE25519_PUBLIC_KEY,
)
from .. import (
    PkEncryption as _DEFAULT_PK_ENCRYPTION,
)
from .. import (
    default_backend as _DEFAULT_DEFAULT_BACKEND,
)
from ..compat import crypto_available, resolve_attribute, vodozemac_pk_available


def _encrypt_backup_data(
    backup_public_key: bytes,
    plaintext: bytes,
) -> tuple[bytes, bytes, bytes]:
    """
    按 Matrix Key Backup v1 规范加密备份数据。

    Returns:
        (ephemeral_public_key, ciphertext, mac)
    """
    if len(backup_public_key) != CRYPTO_KEY_SIZE_32:
        raise ValueError(
            f"备份公钥长度无效：期望 {CRYPTO_KEY_SIZE_32} 字节，实际 {len(backup_public_key)} 字节"
        )

    if vodozemac_pk_available(_DEFAULT_VODOZEMAC_PK_AVAILABLE):
        public_key_cls = resolve_attribute(
            "Curve25519PublicKey",
            _DEFAULT_CURVE25519_PUBLIC_KEY,
        )
        pk_encryption_cls = resolve_attribute(
            "PkEncryption",
            _DEFAULT_PK_ENCRYPTION,
        )
        public_key = public_key_cls.from_base64(
            base64.b64encode(backup_public_key).decode()
        )
        message = pk_encryption_cls.from_key(public_key).encrypt(plaintext)
        return message.ephemeral_key, message.ciphertext, message.mac

    if not crypto_available(_DEFAULT_CRYPTO_AVAILABLE):
        raise RuntimeError("需要 cryptography 或 vodozemac 库来加密密钥备份")

    from cryptography.hazmat.primitives import hashes, padding, serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    backend_factory = resolve_attribute(
        "default_backend",
        _DEFAULT_DEFAULT_BACKEND,
    )
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    recipient_public_key = x25519.X25519PublicKey.from_public_bytes(backup_public_key)
    shared_secret = ephemeral_private_key.exchange(recipient_public_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_KEY_MATERIAL_LEN,
        salt=b"\x00" * CRYPTO_KEY_SIZE_32,
        info=HKDF_MEGOLM_BACKUP_INFO,
        backend=backend_factory(),
    )
    key_material = hkdf.derive(shared_secret)
    encryption_key = key_material[:CRYPTO_KEY_SIZE_32]
    mac_key = key_material[CRYPTO_KEY_SIZE_32 : CRYPTO_KEY_SIZE_32 * 2]

    padder = padding.PKCS7(AES_BLOCK_SIZE_16 * 8).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.CTR(b"\x00" * AES_BLOCK_SIZE_16),
        backend=backend_factory(),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()[:MAC_TRUNCATED_BYTES_8]

    return ephemeral_public_key, ciphertext, mac

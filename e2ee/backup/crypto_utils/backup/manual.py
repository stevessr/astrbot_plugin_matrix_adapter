"""Pure-Python Matrix key-backup decryption fallback."""

from astrbot.api import logger

from .. import (
    CRYPTO_KEY_SIZE_32,
    HKDF_KEY_MATERIAL_LEN,
    HKDF_MEGOLM_BACKUP_INFO,
    MAC_TRUNCATED_BYTES_8,
)


def _manual_decrypt_v1(
    private_key_bytes: bytes,
    ephemeral_key_bytes: bytes,
    ciphertext: bytes,
    mac: bytes,
) -> bytes | None:
    """
    手动实现 Matrix Key Backup v1 解密 (curve25519-aes-sha2)
    Spec: https://spec.matrix.org/v1.9/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2
    """
    try:
        import hashlib
        import hmac

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, padding
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        # 1. ECDH: Calculate shared secret
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
        public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_key_bytes)
        shared_secret = private_key.exchange(public_key)

        # 2. Derive encryption key and MAC key via HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=HKDF_KEY_MATERIAL_LEN,
            salt=b"\x00" * CRYPTO_KEY_SIZE_32,
            info=HKDF_MEGOLM_BACKUP_INFO,
            backend=default_backend(),
        )
        key_material = hkdf.derive(shared_secret)

        encryption_key = key_material[:CRYPTO_KEY_SIZE_32]
        mac_key = key_material[CRYPTO_KEY_SIZE_32:]

        # 3. Verify MAC (8 bytes truncated)
        h = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()[
            :MAC_TRUNCATED_BYTES_8
        ]
        if h != mac:
            logger.warning("MAC 校验失败，密钥或数据可能不正确")
            return None

        # 4. AES-256-CTR decrypt
        # 根据 Matrix 规范，IV 应为 16 字节零向量
        # 参考：https://spec.matrix.org/latest/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CTR(b"\x00" * 16),  # 16 字节零向量作为 IV
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # 5. Remove PKCS#7 padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

        return plaintext
    except Exception as e:
        logger.warning(f"手动解密失败：{e}")
        return None

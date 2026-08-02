"""Matrix m.megolm_backup.v1 encryption and decryption helpers."""

import base64
import hashlib
import hmac

from astrbot.api import logger

from ....constants import (
    AES_BLOCK_SIZE_16,
    CRYPTO_KEY_SIZE_32,
    HKDF_KEY_MATERIAL_LEN,
    HKDF_MEGOLM_BACKUP_INFO,
    MAC_TRUNCATED_BYTES_8,
)
from . import CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE
from . import VODOZEMAC_PK_AVAILABLE as _DEFAULT_VODOZEMAC_PK_AVAILABLE
from . import Curve25519PublicKey as _DEFAULT_CURVE25519_PUBLIC_KEY
from . import PkEncryption as _DEFAULT_PK_ENCRYPTION
from . import default_backend as _DEFAULT_DEFAULT_BACKEND
from .compat import crypto_available, resolve_attribute, vodozemac_pk_available


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


def _decrypt_backup_data(
    private_key_bytes: bytes,
    ephemeral_public_key: bytes,
    ciphertext: bytes,
    mac: bytes,
) -> bytes | None:
    """
    解密 Matrix 密钥备份数据 (m.megolm_backup.v1.curve25519-aes-sha2)

    使用 vodozemac 的 PkDecryption 直接解密，它内部处理：
    1. ECDH: 使用私钥和临时公钥计算共享密钥
    2. 密钥派生和 AES 解密
    3. MAC 验证（虽然有已知缺陷）

    Args:
        private_key_bytes: 32 字节私钥
        ephemeral_public_key: 32 字节临时公钥 (来自备份数据的 ephemeral)
        ciphertext: 加密的数据
        mac: MAC 数据

    Returns:
        解密后的明文，或 None
    """
    try:
        from vodozemac import (
            Curve25519SecretKey,
            PkDecryption,
        )

        # Try to import PkDecodeException if available
        try:
            from vodozemac import PkDecodeException  # noqa: F401
        except ImportError:
            pass

        logger.debug(
            f"使用 vodozemac 解密：private_key={len(private_key_bytes)}B, "
            f"ephemeral={len(ephemeral_public_key)}B, ciphertext={len(ciphertext)}B, mac={len(mac)}B"
        )

        if len(ephemeral_public_key) != CRYPTO_KEY_SIZE_32:
            raise ValueError(
                f"ephemeral 公钥长度无效：期望 {CRYPTO_KEY_SIZE_32} 字节，实际 {len(ephemeral_public_key)} 字节"
            )

        # 创建 PkDecryption 对象
        secret_key = Curve25519SecretKey.from_bytes(private_key_bytes)
        pk_decryption = PkDecryption.from_key(secret_key)

        # 创建 Message 对象 - vodozemac 需要特定格式
        # 尝试直接传递字节数据解密
        try:
            # 方法 1: 使用 vodozemac 的内部 Message 格式
            from vodozemac import Message as VodozemacMessage

            # 尝试从 base64 格式创建
            # 参数顺序：from_base64(ciphertext, mac, ephemeral_key)
            ephemeral_key_b64 = base64.b64encode(ephemeral_public_key).decode()
            ciphertext_b64 = base64.b64encode(ciphertext).decode()
            mac_b64 = base64.b64encode(mac).decode()

            # 正确的参数顺序：ciphertext, mac, ephemeral_key
            message = VodozemacMessage.from_base64(
                ciphertext_b64, mac_b64, ephemeral_key_b64
            )
            plaintext = pk_decryption.decrypt(message)

            return plaintext

        except BaseException as e1:
            # 捕获所有异常类型（包括 vodozemac 的特殊异常）
            error_msg = str(e1)
            logger.warning(f"vodozemac 解密失败 ({error_msg})，尝试手动解密...")

            # Fallback to manual decryption
            return _manual_decrypt_v1(
                private_key_bytes, ephemeral_public_key, ciphertext, mac
            )

    except ImportError:
        logger.warning("vodozemac 未安装，使用 Python 原生实现")
        return _manual_decrypt_v1(
            private_key_bytes, ephemeral_public_key, ciphertext, mac
        )
    except Exception as e:
        logger.error(f"初始化 vodozemac 失败：{e}")
        return _manual_decrypt_v1(
            private_key_bytes, ephemeral_public_key, ciphertext, mac
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

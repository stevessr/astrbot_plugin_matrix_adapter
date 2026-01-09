import base64
import hashlib
import hmac
import secrets

from astrbot.api import logger

from ..constants import (
    AES_GCM_NONCE_LEN,
    BASE58_ALPHABET,
    CRYPTO_KEY_SIZE_32,
    HKDF_KEY_MATERIAL_LEN,
    HKDF_MEGOLM_BACKUP_INFO,
    MAC_TRUNCATED_BYTES_8,
    RECOVERY_KEY_HDR_BYTE1,
    RECOVERY_KEY_HDR_BYTE2,
    RECOVERY_KEY_PRIV_LEN,
    RECOVERY_KEY_TOTAL_LEN,
)

# 尝试导入加密库
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import hmac as crypto_hmac  # noqa: F401
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.debug("cryptography 库不可用，密钥备份将使用简化加密")

# 尝试导入 vodozemac (用于 Matrix 兼容的 PkDecryption)
try:
    from vodozemac import (  # noqa: F401
        Curve25519SecretKey,
        PkDecodeException,
        PkDecryption,
    )

    VODOZEMAC_PK_AVAILABLE = True
except ImportError:
    VODOZEMAC_PK_AVAILABLE = False
    Curve25519SecretKey = None
    PkDecryption = None
    PkDecodeException = Exception  # 回退到通用异常
    logger.debug("vodozemac PkDecryption 不可用")


def _compute_hkdf(
    input_key: bytes, salt: bytes, info: bytes, length: int = CRYPTO_KEY_SIZE_32
) -> bytes:
    """计算 HKDF-SHA256"""
    if CRYPTO_AVAILABLE:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt if salt else None,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(input_key)
    else:
        # 简化的 HKDF 实现
        if not salt:
            salt = b"\x00" * CRYPTO_KEY_SIZE_32
        prk = hmac.new(salt, input_key, hashlib.sha256).digest()
        output = b""
        t = b""
        counter = 1
        while len(output) < length:
            t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
            output += t
            counter += 1
        return output[:length]


def _aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """AES-GCM 加密"""
    nonce = secrets.token_bytes(AES_GCM_NONCE_LEN)
    if CRYPTO_AVAILABLE:
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    else:
        # 简化实现 (不安全，仅用于测试)
        ciphertext = bytes(
            a ^ b for a, b in zip(plaintext, key * (len(plaintext) // len(key) + 1))
        )
    return nonce, ciphertext


def _aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """AES-GCM 解密"""
    if CRYPTO_AVAILABLE:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    else:
        # 简化实现 (不安全，仅用于测试)
        return bytes(
            a ^ b for a, b in zip(ciphertext, key * (len(ciphertext) // len(key) + 1))
        )


def _aes_ctr_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    AES-256-CTR 解密 (Matrix 密钥备份使用此模式)
    """
    if CRYPTO_AVAILABLE:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    else:
        # 无法使用简化实现，因为 CTR 模式需要正确的计数器处理
        raise RuntimeError("需要 cryptography 库来解密密钥备份")


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


def _encode_recovery_key(key_bytes: bytes) -> str:
    """
    将 32 字节密钥编码为 Matrix 恢复密钥 (Base58)
    """
    if len(key_bytes) != RECOVERY_KEY_PRIV_LEN:
        raise ValueError("恢复密钥长度必须为 32 字节")

    data = bytearray()
    data.append(RECOVERY_KEY_HDR_BYTE1)
    data.append(RECOVERY_KEY_HDR_BYTE2)
    data.extend(key_bytes)

    checksum = 0
    for b in data:
        checksum ^= b
    data.append(checksum)

    # Base58 编码
    value = int.from_bytes(data, "big")
    encoded = ""
    while value > 0:
        value, rem = divmod(value, 58)
        encoded = BASE58_ALPHABET[rem] + encoded

    # 补前导零
    for b in data:
        if b == 0:
            encoded = BASE58_ALPHABET[0] + encoded
        else:
            break

    # 每 4 字符插入空格（可读格式）
    groups = [encoded[i : i + 4] for i in range(0, len(encoded), 4)]
    return " ".join(groups)


def _decode_recovery_key(key_str: str) -> bytes:
    """
    解析 Matrix 恢复密钥 (Base58 或 Base64)
    """
    key_str = key_str.replace(" ", "")

    # 尝试 Base58（标准恢复密钥格式）
    try:
        value = 0
        for c in key_str:
            value = value * 58 + BASE58_ALPHABET.index(c)

        decoded = value.to_bytes(RECOVERY_KEY_TOTAL_LEN, "big")
        if (
            len(decoded) != RECOVERY_KEY_TOTAL_LEN
            or decoded[0] != RECOVERY_KEY_HDR_BYTE1
            or decoded[1] != RECOVERY_KEY_HDR_BYTE2
        ):
            raise ValueError("恢复密钥头部不匹配，应为 0x8B01")

        checksum = 0
        for b in decoded[:-1]:
            checksum ^= b
        if checksum != decoded[-1]:
            raise ValueError("恢复密钥校验失败 (XOR mismatch)")

        private_key = decoded[2 : 2 + RECOVERY_KEY_PRIV_LEN]
        return private_key
    except Exception as e:
        logger.warning(f"Base58 恢复密钥解析失败：{e}")

    # 尝试 Base64（兼容旧格式或直接私钥字符串）
    try:
        decoded = base64.b64decode(key_str + "===")

        if (
            len(decoded) >= RECOVERY_KEY_TOTAL_LEN
            and decoded[0] == RECOVERY_KEY_HDR_BYTE1
            and decoded[1] == RECOVERY_KEY_HDR_BYTE2
        ):
            checksum = 0
            for b in decoded[:-1]:
                checksum ^= b
            if checksum != decoded[-1]:
                raise ValueError("Base64 恢复密钥校验失败 (XOR mismatch)")
            return decoded[2 : 2 + RECOVERY_KEY_PRIV_LEN]

        if len(decoded) >= RECOVERY_KEY_PRIV_LEN:
            return decoded[:RECOVERY_KEY_PRIV_LEN]
    except Exception:
        logger.debug("Base64 解码失败，尝试其他格式")

    raise ValueError("无法解码恢复密钥，请检查输入格式（应为 Matrix Base58 或 Base64）")

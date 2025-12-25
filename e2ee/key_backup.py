"""
Key Backup - Matrix 密钥备份

实现 Megolm 会话密钥的服务器端备份和恢复。
使用用户配置的恢复密钥进行加密。
"""

import base64
import hashlib
import hmac
import json
import secrets
from pathlib import Path

from astrbot.api import logger

from ..client.http_client import MatrixAPIError
from ..constants import (
    AES_GCM_NONCE_LEN,
    BASE58_ALPHABET,
    CRYPTO_KEY_SIZE_32,
    DEHYDRATED_DEVICE_EVENT,
    HKDF_KEY_MATERIAL_LEN,
    HKDF_MEGOLM_BACKUP_INFO,
    MAC_TRUNCATED_BYTES_8,
    MEGOLM_BACKUP_ALGO,
    MSC2697_DEHYDRATED_DEVICE_EVENT,
    RECOVERY_KEY_HDR_BYTE1,
    RECOVERY_KEY_HDR_BYTE2,
    RECOVERY_KEY_MAC_TRUNCATED_LEN,
    RECOVERY_KEY_PRIV_LEN,
    RECOVERY_KEY_TOTAL_LEN,
    SSSS_BACKUP_SECRET,
    SSSS_DEFAULT_KEY,
    SSSS_KEY_PREFIX,
)

# 尝试导入加密库
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import hmac as crypto_hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.debug("cryptography 库不可用，密钥备份将使用简化加密")

# 尝试导入 vodozemac (用于 Matrix 兼容的 PkDecryption)
try:
    from vodozemac import Curve25519SecretKey, PkDecodeException, PkDecryption

    VODOZEMAC_PK_AVAILABLE = True
except ImportError:
    VODOZEMAC_PK_AVAILABLE = False
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
            Curve25519PublicKey,
            Curve25519SecretKey,
            PkDecryption,
        )

        # Try to import PkDecodeException if available
        try:
            from vodozemac import PkDecodeException
        except ImportError:
            PkDecodeException = Exception

        logger.info(
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

            logger.info(f"vodozemac 解密成功！明文长度={len(plaintext)}B")
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

        # 2. HKDF: Derive keys
        # Info MUST be "m.megolm_backup.v1"
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=HKDF_KEY_MATERIAL_LEN,
            salt=b"",
            info=HKDF_MEGOLM_BACKUP_INFO,
            backend=default_backend(),
        )
        key_material = hkdf.derive(shared_secret)

        aes_key = key_material[:CRYPTO_KEY_SIZE_32]
        mac_key = key_material[CRYPTO_KEY_SIZE_32:64]
        aes_iv = key_material[64:80]

        # 3. MAC Verification
        h = hmac.new(mac_key, ciphertext, hashlib.sha256)
        full_mac = h.digest()

        # Spec: "The MAC is the first 8 bytes of the HMAC-SHA-256 of the ciphertext."
        # Check if provided mac matches the first 8 bytes OR full bytes
        if len(mac) == RECOVERY_KEY_MAC_TRUNCATED_LEN:
            if not hmac.compare_digest(mac, full_mac[:MAC_TRUNCATED_BYTES_8]):
                logger.warning(
                    f"Manual: MAC mismatch (8 bytes). "
                    f"Expected={full_mac[:8].hex()}, Got={mac.hex()}"
                )
                return None
        else:
            if not hmac.compare_digest(mac, full_mac):
                logger.warning("Manual: MAC mismatch (full)")
                return None

        # 4. AES-CBC Decryption
        cipher = Cipher(
            algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # 5. PKCS7 Unpadding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

        logger.info(f"Manual: 解密成功！长度={len(plaintext)}B")
        return plaintext

    except Exception as e:
        logger.error(f"Manual decryption failed: {e}")
        return None


def _encode_recovery_key(key_bytes: bytes) -> str:
    """按照 Matrix 规范将 32 字节私钥编码为 Base58 恢复密钥字符串"""

    # 只使用前 32 字节，多余部分截断，不足补零
    key_bytes = (key_bytes or b"").ljust(CRYPTO_KEY_SIZE_32, b"\x00")[
        :CRYPTO_KEY_SIZE_32
    ]

    # 前缀头 0x8B 0x01 + 私钥 + 校验（前面所有字节的 XOR）
    payload = bytes([RECOVERY_KEY_HDR_BYTE1, RECOVERY_KEY_HDR_BYTE2]) + key_bytes
    checksum = 0
    for b in payload:
        checksum ^= b
    payload += bytes([checksum])

    # Base58 编码（比特币字符集）
    alphabet = BASE58_ALPHABET
    n = int.from_bytes(payload, "big")
    encoded = ""
    while n > 0:
        n, rem = divmod(n, 58)
        encoded = alphabet[rem] + encoded

    # 保留前导零
    leading_zeros = len(payload) - len(payload.lstrip(b"\x00"))
    encoded = ("1" * leading_zeros) + encoded

    # 为易读性每 4 字符分组（解码时会去掉空格）
    return " ".join(encoded[i : i + 4] for i in range(0, len(encoded), 4))


def _decode_recovery_key(key_str: str) -> bytes:
    """
    解码用户提供的恢复密钥

    支持多种格式：
    - Matrix 标准 base58 恢复密钥 (以 Es 开头，格式：0x8B 0x01 + 32 字节密钥 + 1 字节校验)
    - Base64 编码的 32 字节密钥
    """
    # 移除空格和破折号，兼容分组显示
    key_str = (key_str or "").replace(" ", "").replace("-", "")
    alphabet = BASE58_ALPHABET

    # 优先尝试 Matrix 规范的 Base58 (58 字符，Bitcoin alphabet)
    if key_str and all(c in alphabet for c in key_str):
        try:
            # Base58 解码，保留前导零
            n = 0
            for char in key_str:
                n = n * 58 + alphabet.index(char)

            decoded = n.to_bytes(RECOVERY_KEY_TOTAL_LEN, "big")
            leading_ones = len(key_str) - len(key_str.lstrip("1"))
            if leading_ones:
                decoded = (b"\x00" * leading_ones) + decoded

            # 规范长度应为 RECOVERY_KEY_TOTAL_LEN 字节：0x8B 0x01 + 32B 密钥 + 1B 校验
            if len(decoded) < RECOVERY_KEY_TOTAL_LEN:
                decoded = decoded.rjust(RECOVERY_KEY_TOTAL_LEN, b"\x00")
            elif len(decoded) > RECOVERY_KEY_TOTAL_LEN:
                decoded = decoded[-RECOVERY_KEY_TOTAL_LEN:]

            # 验证头与校验
            if (
                decoded[0] != RECOVERY_KEY_HDR_BYTE1
                or decoded[1] != RECOVERY_KEY_HDR_BYTE2
            ):
                raise ValueError("恢复密钥头部不匹配，应为 0x8B01")

            checksum = 0
            for b in decoded[:-1]:
                checksum ^= b
            if checksum != decoded[-1]:
                raise ValueError("恢复密钥校验失败 (XOR mismatch)")

            private_key = decoded[2 : 2 + RECOVERY_KEY_PRIV_LEN]
            logger.info("成功解析 Base58 恢复密钥")
            return private_key
        except Exception as e:
            logger.warning(f"Base58 恢复密钥解析失败：{e}")

    # 尝试 Base64（兼容旧格式或直接私钥字符串）
    try:
        decoded = base64.b64decode(key_str + "===")
        logger.info(f"Base64 解码：{len(decoded)}B")

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


class KeyBackup:
    """
    密钥备份管理器

    使用用户配置的恢复密钥进行加密，支持：
    - 创建密钥备份
    - 上传 Megolm 会话密钥到备份
    - 从备份恢复密钥
    """

    def __init__(
        self,
        client,
        crypto_store,
        olm_machine,
        recovery_key: str = "",
        store_path: str = "",
    ):
        """
        初始化密钥备份

        Args:
            client: MatrixHTTPClient
            crypto_store: CryptoStore
            olm_machine: OlmMachine
            recovery_key: 用户配置的恢复密钥 (base58)
            store_path: 存储路径（用于持久化提取的备份密钥）
        """
        self.client = client
        self.store = crypto_store
        self.olm = olm_machine
        self.store_path = store_path

        self._backup_version: str | None = None
        self._backup_auth_data: dict = {}
        self._recovery_key_bytes: bytes | None = None
        self._encryption_key: bytes | None = None
        self._original_recovery_key_str: str = recovery_key  # 保存原始输入

        # 处理用户提供的恢复密钥
        if recovery_key:
            try:
                self._recovery_key_bytes = _decode_recovery_key(recovery_key)
                self._encryption_key = _compute_hkdf(
                    self._recovery_key_bytes, b"", HKDF_MEGOLM_BACKUP_INFO
                )
                logger.info("使用用户配置的恢复密钥")
            except Exception as e:
                logger.error(f"解析恢复密钥失败：{e}")

    def _get_extracted_key_path(self) -> str:
        """获取提取的备份密钥存储路径"""
        if self.store_path:
            from pathlib import Path

            return str(Path(self.store_path) / "extracted_backup_key.bin")
        return ""

    def _save_extracted_key(self, key_bytes: bytes):
        """保存从 SSSS 提取的备份密钥到本地"""
        try:
            path = self._get_extracted_key_path()
            if not path:
                return

            from pathlib import Path

            Path(path).parent.mkdir(parents=True, exist_ok=True)

            with open(path, "wb") as f:
                f.write(key_bytes)

            logger.info(f"已保存提取的备份密钥到 {path}")
        except Exception as e:
            logger.warning(f"保存提取的备份密钥失败：{e}")

    def _load_extracted_key(self) -> bytes | None:
        """从本地加载之前提取的备份密钥"""
        try:
            path = self._get_extracted_key_path()
            if not path:
                return None

            from pathlib import Path

            if not Path(path).exists():
                return None

            with open(path, "rb") as f:
                key_bytes = f.read()

            if len(key_bytes) == CRYPTO_KEY_SIZE_32:
                logger.info("从本地加载了提取的备份密钥")
                return key_bytes
            else:
                logger.warning(f"本地备份密钥长度不正确：{len(key_bytes)} bytes")
                return None
        except Exception as e:
            logger.debug(f"加载提取的备份密钥失败：{e}")
            return None

    async def _try_restore_from_secret_storage(
        self, provided_key_bytes: bytes
    ) -> bytes | None:
        """
        尝试从 Secret Storage 解密真正的备份密钥
        支持直接解密和通过 Recovery Key 解密 SSSS Key 的链式解密
        """
        logger.info("尝试从 Secret Storage 恢复密钥...")
        dehydrated_device = None
        try:
            # 1. Get default key ID
            default_key_data = await self.client.get_global_account_data(
                SSSS_DEFAULT_KEY
            )
            key_id = default_key_data.get("key")
            if not key_id:
                logger.warning(
                    "SSSS Account Data 'm.secret_storage.default_key' 未找到或无 'key'"
                )
                return None

            logger.info(f"SSSS Default Key ID: {key_id}")

            # 2. Try to decrypt the SSSS Key itself (if it's encrypted by the provided key)
            # Fetch key definition
            key_data = await self.client.get_global_account_data(
                f"{SSSS_KEY_PREFIX}{key_id}"
            )
            # DEBUG LOGGING
            if key_data:
                logger.info(f"Key Data for {key_id}: keys={list(key_data.keys())}")
                if "encrypted" in key_data:
                    logger.info(
                        f"Key {key_id} has encrypted data: {list(key_data['encrypted'].keys())}"
                    )
                else:
                    logger.warning(
                        f"Key data for {key_id} does not contain 'encrypted' section"
                    )
            else:
                logger.warning(f"Could not fetch data for key {key_id}")
                # Check for Dehydrated Device
                dehydrated_device = await self.client.get_global_account_data(
                    DEHYDRATED_DEVICE_EVENT
                )
                if not dehydrated_device:
                    dehydrated_device = await self.client.get_global_account_data(
                        MSC2697_DEHYDRATED_DEVICE_EVENT
                    )
                    if dehydrated_device:
                        logger.info("Found MSC2697 dehydrated device event")
            if dehydrated_device:
                logger.info(
                    f"Found dehydrated device event: {dehydrated_device.keys()}"
                )
                device_data = dehydrated_device.get("device_data", {})
                if device_data:
                    logger.info(f"Dehydrated device data keys: {device_data.keys()}")
                    # Try to decrypt using provided key (dehydrated device key from FluffyChat)
                    # Dehydrated device uses "org.matrix.msc2697.dehydrated_device" or "m.dehydrated_device" as secret name
                    decrypted_device = self._decrypt_ssss_data(
                        provided_key_bytes,
                        device_data,
                        secret_name="m.dehydrated_device",
                    )
                    if decrypted_device:
                        logger.info("✅ Successfully decrypted Dehydrated Device data!")
                        # The decrypted data might contain the actual backup recovery key
                        # Try to extract it and use it as the SSSS key
                        try:
                            import json

                            # Try to parse as JSON first
                            try:
                                device_info = json.loads(decrypted_device)
                                logger.info(
                                    f"Decrypted Dehydrated Device Info keys: {device_info.keys()}"
                                )

                                # Look for backup key in common locations
                                # FluffyChat might store it as 'm.megolm_backup.v1' or similar
                                backup_key = None
                                if "m.megolm_backup.v1" in device_info:
                                    backup_key = device_info["m.megolm_backup.v1"]
                                    logger.info(
                                        "Found backup key in dehydrated device: m.megolm_backup.v1"
                                    )
                                elif "backup_key" in device_info:
                                    backup_key = device_info["backup_key"]
                                    logger.info(
                                        "Found backup key in dehydrated device: backup_key"
                                    )

                                if backup_key:
                                    # The backup key might be base64 encoded
                                    if isinstance(backup_key, str):
                                        try:
                                            extracted_key = base64.b64decode(backup_key)
                                            logger.info(
                                                f"✅ Extracted backup key from dehydrated device ({len(extracted_key)} bytes)"
                                            )
                                            # Use this as the actual recovery key!
                                            return extracted_key
                                        except:
                                            logger.warning(
                                                "Failed to base64 decode backup key from device"
                                            )
                                    elif isinstance(backup_key, bytes):
                                        logger.info(
                                            f"✅ Extracted backup key from dehydrated device ({len(backup_key)} bytes)"
                                        )
                                        return backup_key

                            except (json.JSONDecodeError, ValueError):
                                # Not JSON, might be pickled Olm account or raw key material
                                logger.info(
                                    f"Decrypted Dehydrated Device data is not JSON (len: {len(decrypted_device)})"
                                )
                                # If it's exactly 32 bytes, it might be the raw backup key
                                if len(decrypted_device) == CRYPTO_KEY_SIZE_32:
                                    logger.info(
                                        "✅ Dehydrated device data is exactly 32 bytes, using as backup key"
                                    )
                                    return decrypted_device
                        except Exception as e:
                            logger.warning(
                                f"Failed to extract backup key from dehydrated device: {e}"
                            )
                    else:
                        logger.warning(
                            "Failed to decrypt Dehydrated Device with provided key"
                        )
            else:
                logger.info("No dehydrated device event found")

            ssss_key = provided_key_bytes
            # If the key definition contains 'encrypted', it means the actual SSSS key is encrypted            # (usually by the Recovery Key or Passphrase)
            if key_data and "encrypted" in key_data:
                logger.info(f"检测到 SSSS Key {key_id} 是加密存储的，尝试解密...")
                encrypted_map = key_data["encrypted"]
                decrypted_ssss_key = None

                # Try all entries in the encrypted map
                for kid, enc_data in encrypted_map.items():
                    # The SSSS key itself uses empty string as secret name
                    decrypted = self._decrypt_ssss_data(
                        provided_key_bytes, enc_data, secret_name=""
                    )
                    if decrypted:
                        logger.info(f"成功使用提供的密钥解密了 SSSS Key (ID: {kid})")
                        decrypted_ssss_key = decrypted
                        break

                if decrypted_ssss_key:
                    # Check if the decrypted key is base64 encoded (it usually is in SSSS)
                    try:
                        # SSSS keys are often stored as base64 string in the payload
                        secret_str = decrypted_ssss_key.decode("utf-8")
                        if len(secret_str.strip()) >= 43:
                            ssss_key = base64.b64decode(secret_str)
                        else:
                            ssss_key = decrypted_ssss_key
                    except:
                        ssss_key = decrypted_ssss_key
                else:
                    logger.warning(
                        "无法解密 SSSS Key，尝试直接使用提供的密钥作为 SSSS Key..."
                    )

            # 3. Get Backup Secret (m.megolm_backup.v1)
            backup_secret_data = await self.client.get_global_account_data(
                SSSS_BACKUP_SECRET
            )
            encrypted_data = backup_secret_data.get("encrypted", {}).get(key_id)

            if not encrypted_data:
                logger.warning(
                    f"Account Data 'm.megolm_backup.v1' 中未找到 Key ID {key_id} 的加密数据"
                )
                return None

            # 4. Decrypt Backup Key using SSSS Key
            # Use the backup secret name (m.megolm_backup.v1) as info for HKDF
            decrypted_secret = self._decrypt_ssss_data(
                ssss_key, encrypted_data, secret_name=SSSS_BACKUP_SECRET
            )

            if decrypted_secret:
                logger.info("SSSS MAC 验证成功，解密备份密钥成功")
                # Check format (usually base64 string in Matrix)
                try:
                    secret_str = decrypted_secret.decode("utf-8")
                    if len(secret_str.strip()) >= 43:
                        return base64.b64decode(secret_str)
                    return decrypted_secret
                except:
                    return decrypted_secret
            else:
                logger.error(
                    "SSSS MAC 验证失败！提供的密钥（或解密出的 SSSS Key）不正确"
                )
                return None

        except Exception as e:
            logger.error(f"SSSS 恢复失败：{e}")
            import traceback

            logger.error(traceback.format_exc())
            return None

    def _decrypt_ssss_data(
        self, key: bytes, encrypted_data: dict, secret_name: str = ""
    ) -> bytes | None:
        """
        解密 SSSS 加密的数据 (AES-CTR-256 + HMAC-SHA-256)

        Per Matrix spec (m.secret_storage.v1.aes-hmac-sha2):
        - Use HKDF to derive 64 bytes from the key
        - First 32 bytes: AES-CTR key
        - Next 32 bytes: HMAC-SHA-256 key
        - HKDF uses SHA-256, 32-byte zero salt, and secret name as info
        """
        ciphertext_b64 = encrypted_data.get("ciphertext")
        iv_b64 = encrypted_data.get("iv")
        mac_b64 = encrypted_data.get("mac")

        if not ciphertext_b64 or not iv_b64 or not mac_b64:
            return None

        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            iv = base64.b64decode(iv_b64)
            mac = base64.b64decode(mac_b64)
        except Exception:
            return None

        if not CRYPTO_AVAILABLE:
            logger.error("缺少 cryptography 库，无法进行 SSSS 解密")
            return None

        # Derive AES and MAC keys using HKDF per Matrix spec
        # HKDF(SHA-256, key, 32-byte zero salt, secret_name as info) -> 64 bytes
        try:
            # Use secret name as info for HKDF derivation
            info = secret_name.encode() if secret_name else b""
            salt = b"\x00" * CRYPTO_KEY_SIZE_32  # Zero salt per spec

            derived = _compute_hkdf(key, salt, info, length=64)
            aes_key = derived[:CRYPTO_KEY_SIZE_32]
            hmac_key = derived[CRYPTO_KEY_SIZE_32:64]

            logger.debug(f"SSSS 密钥派生：info={repr(info)}, 派生 64 字节")
        except Exception as e:
            logger.warning(f"HKDF 密钥派生失败：{e}, 使用原始密钥")
            # Fallback: use key directly (backward compatibility)
            aes_key = key
            hmac_key = key

        # Verify MAC
        try:
            h = crypto_hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(ciphertext)
            try:
                h.verify(mac)
            except Exception:
                return None

            # Decrypt
            return _aes_ctr_decrypt(aes_key, iv, ciphertext)
        except Exception as e:
            logger.warning(f"解密异常：{e}")
            return None

    async def initialize(self):
        """初始化密钥备份"""
        try:
            version = await self._get_current_backup_version()
            if version:
                self._backup_version = version
                logger.info(f"发现现有密钥备份：version={version}")

                # 验证现有密钥
                if self._recovery_key_bytes:
                    # 先尝试直接验证
                    if not self._verify_recovery_key(self._recovery_key_bytes):
                        logger.warning(
                            "恢复密钥与备份公钥不匹配，尝试按 Secret Storage Key 处理..."
                        )

                        # 尝试加载之前保存的提取密钥
                        extracted_key = self._load_extracted_key()
                        if extracted_key and self._verify_recovery_key(extracted_key):
                            logger.info("✅ 使用本地保存的提取密钥成功验证！")
                            self._recovery_key_bytes = extracted_key
                            self._encryption_key = _compute_hkdf(
                                self._recovery_key_bytes,
                                b"",
                                HKDF_MEGOLM_BACKUP_INFO,
                            )
                        else:
                            # 本地没有或验证失败，从 SSSS 提取
                            real_key = await self._try_restore_from_secret_storage(
                                self._recovery_key_bytes
                            )
                            if real_key:
                                logger.info("从 SSSS 成功提取密钥，再次验证...")
                                if self._verify_recovery_key(real_key):
                                    logger.info("✅ 成功获取并验证了真正的备份密钥！")
                                    self._recovery_key_bytes = real_key
                                    self._encryption_key = _compute_hkdf(
                                        self._recovery_key_bytes,
                                        b"",
                                        HKDF_MEGOLM_BACKUP_INFO,
                                    )
                                    # 保存提取的密钥到本地
                                    self._save_extracted_key(real_key)
                                else:
                                    logger.error("SSSS 提取的密钥验证失败")
                            else:
                                logger.error("无法通过 SSSS 恢复密钥")
                    else:
                        logger.info("✅ 恢复密钥与备份版本公钥匹配")
            else:
                logger.info("未发现密钥备份")
        except Exception as e:
            logger.warning(f"初始化失败：{e}")

    async def _get_current_backup_version(self) -> str | None:
        """获取当前备份版本"""
        try:
            response = await self.client._request(
                "GET", "/_matrix/client/v3/room_keys/version"
            )
            version = response.get("version")
            if version:
                self._backup_auth_data = response.get("auth_data", {})
            return version
        except Exception:
            return None

    def _verify_recovery_key(self, key_bytes: bytes) -> bool:
        """验证恢复密钥是否与当前备份匹配"""
        if not self._backup_auth_data:
            return True  # 无法验证，假设正确

        try:
            expected_public_key = self._backup_auth_data.get("public_key")
            if not expected_public_key:
                return True

            # Always use cryptography for verification to generate consistent Public Key
            import base64

            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import x25519

            # Derive Public Key from Private Key
            priv = x25519.X25519PrivateKey.from_private_bytes(key_bytes)
            pub = priv.public_key()

            # Matrix uses unpadded base64 representation of the raw bytes
            pub_bytes = pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            public_key = base64.urlsafe_b64encode(pub_bytes).decode().rstrip("=")

            # Matrix backup public key is usually standard base64? Let's check spec.
            # Spec says "The public key, encoded as unpadded base64." which usually means base64.b64encode (standard) or urlsafe?
            # Curve25519 public keys are CRYPTO_KEY_SIZE_32 bytes.
            # Usually Matrix uses unpadded Base64 (RFC 4648 without pad).
            # Let's try standard b64encode first as it's more common for keys in Matrix except for identifiers.

            public_key_std = base64.b64encode(pub_bytes).decode().rstrip("=")

            if (
                public_key_std != expected_public_key
                and public_key != expected_public_key
            ):
                logger.error("❌ 恢复密钥不匹配！")
                logger.error(f"备份版本要求公钥：{expected_public_key}")
                logger.error(f"您的密钥生成公钥：{public_key_std} (或者 {public_key})")

                # Check if it matches after padding?
                return False

            logger.info(f"✅ 恢复密钥与备份版本公钥匹配 ({expected_public_key})")
            return True

        except Exception as e:
            logger.warning(f"验证密钥失败：{e}")
            import traceback

            logger.warning(traceback.format_exc())
            return True

    async def create_backup(self) -> tuple[str, str] | None:
        """
        创建新的密钥备份

        Returns:
            (version, recovery_key) 或 None
        """
        try:
            # 如果没有提供恢复密钥，生成新的
            if not self._recovery_key_bytes:
                self._recovery_key_bytes = secrets.token_bytes(CRYPTO_KEY_SIZE_32)
                self._encryption_key = _compute_hkdf(
                    self._recovery_key_bytes, b"", b"m.megolm_backup.v1"
                )
                recovery_key_str = _encode_recovery_key(self._recovery_key_bytes)

                logger.warning("" + "=" * 50)
                logger.warning("⚠️  新生成的恢复密钥（请务必保存）:")
                logger.warning(f"{recovery_key_str}")
                logger.warning("可将此密钥配置到 matrix_e2ee_recovery_key")
                logger.warning("" + "=" * 50)
            else:
                recovery_key_str = _encode_recovery_key(self._recovery_key_bytes)

            # 生成用于备份的公钥
            # 使用恢复密钥的 SHA256 作为 "公钥" (简化实现)
            public_key = base64.b64encode(
                hashlib.sha256(self._recovery_key_bytes).digest()
            ).decode()

            # 创建备份
            response = await self.client._request(
                "POST",
                "/_matrix/client/v3/room_keys/version",
                data={
                    "algorithm": MEGOLM_BACKUP_ALGO,
                    "auth_data": {
                        "public_key": public_key,
                    },
                },
            )

            version = response.get("version")
            if version:
                self._backup_version = version
                logger.info(f"创建备份成功：version={version}")
                return (version, recovery_key_str)

        except Exception as e:
            logger.error(f"创建备份失败：{e}")
        return None

    async def upload_room_keys(self, room_id: str | None = None):
        """
        上传房间密钥到备份

        Args:
            room_id: 可选，指定房间 ID
        """
        if not self._backup_version or not self._encryption_key:
            logger.warning("未创建备份或无加密密钥，无法上传")
            return

        try:
            sessions = self.store._megolm_inbound
            if not sessions:
                logger.debug("没有可上传的会话密钥")
                return

            rooms: dict[str, dict[str, dict]] = {}

            for session_id, pickle in sessions.items():
                # 加密会话数据
                plaintext = pickle.encode() if isinstance(pickle, str) else pickle
                nonce, ciphertext = _aes_encrypt(self._encryption_key, plaintext)

                session_data = {
                    "first_message_index": 0,
                    "forwarded_count": 0,
                    "is_verified": True,
                    "session_data": {
                        "ciphertext": base64.b64encode(ciphertext).decode(),
                        "mac": base64.b64encode(
                            hmac.new(
                                self._encryption_key, ciphertext, hashlib.sha256
                            ).digest()[:RECOVERY_KEY_MAC_TRUNCATED_LEN]
                        ).decode(),
                        "ephemeral": base64.b64encode(nonce).decode(),
                    },
                }

                target_room = room_id or "unknown"
                if target_room not in rooms:
                    rooms[target_room] = {}
                rooms[target_room][session_id] = session_data

            await self.client._request(
                "PUT",
                f"/_matrix/client/v3/room_keys/keys?version={self._backup_version}",
                data={"rooms": rooms},
            )

            logger.info(f"已上传 {len(sessions)} 个会话密钥")

        except Exception as e:
            logger.error(f"上传密钥失败：{e}")

    async def restore_room_keys(self, recovery_key: str | None = None):
        """
        从备份恢复密钥

        Args:
            recovery_key: 恢复密钥 (覆盖初始化时的密钥)
        """
        if not self._backup_version:
            logger.warning("未发现备份，无法恢复")
            return

        # 确定使用的恢复密钥
        key_bytes = None
        if recovery_key:
            try:
                key_bytes = _decode_recovery_key(recovery_key)
            except Exception as e:
                logger.error(f"解析恢复密钥失败：{e}")
                return
        elif self._recovery_key_bytes:
            key_bytes = self._recovery_key_bytes
        else:
            logger.error("无恢复密钥，无法解密备份")
            return

        # 验证密钥是否匹配备份版本
        if not self._verify_recovery_key(key_bytes):
            return

        # 创建 PkDecryption 对象 (如果 vodozemac 可用)
        _pk_decryption = None
        if VODOZEMAC_PK_AVAILABLE:
            try:
                # key_bytes 需要转换为 Curve25519SecretKey 对象
                secret_key = Curve25519SecretKey.from_bytes(key_bytes)
                _pk_decryption = PkDecryption.from_key(secret_key)
                logger.debug("使用 vodozemac PkDecryption 解密备份")
            except Exception as e:
                logger.warning(f"创建 PkDecryption 失败：{e}")

        try:
            logger.info(f"开始从备份恢复密钥 (version={self._backup_version})")
            response = await self.client._request(
                "GET",
                f"/_matrix/client/v3/room_keys/keys?version={self._backup_version}",
            )

            rooms = response.get("rooms", {})
            total_sessions = sum(len(s) for s in rooms.values())
            logger.info(f"获取到 {len(rooms)} 个房间，共 {total_sessions} 个会话")

            restored = 0
            skipped = 0

            for room_id, room_data in rooms.items():
                # API 返回格式：rooms[room_id] = {"sessions": {session_id: {...}}}
                sessions = room_data.get("sessions", room_data)
                if not isinstance(sessions, dict):
                    sessions = room_data  # 回退到直接使用 room_data
                for session_id, session_data in sessions.items():
                    try:
                        encrypted_data = session_data.get("session_data", {})
                        # 记录数据结构以便调试
                        logger.info(
                            f"会话 {session_id[:8]}... 数据结构：{list(encrypted_data.keys())}"
                        )
                        # 获取加密数据
                        ciphertext_b64 = encrypted_data.get("ciphertext", "")
                        ephemeral_b64 = encrypted_data.get("ephemeral", "")
                        mac_b64 = encrypted_data.get("mac", "")
                        logger.info(
                            f"ciphertext={bool(ciphertext_b64)}, "
                            f"ephemeral={bool(ephemeral_b64)}, mac={bool(mac_b64)}"
                        )

                        if not ciphertext_b64:
                            logger.warning(f"会话 {session_id[:8]}... 无 ciphertext")
                            skipped += 1
                            continue

                        plaintext = None

                        # 尝试使用 Matrix 标准备份解密 (m.megolm_backup.v1.curve25519-aes-sha2)
                        if ephemeral_b64 and mac_b64:
                            try:
                                # Matrix 使用无填充的 base64url 编码
                                def decode_unpadded_base64(s: str) -> bytes:
                                    # 添加缺失的填充
                                    padding = 4 - len(s) % 4
                                    if padding != 4:
                                        s += "=" * padding
                                    # 尝试标准 base64，然后 urlsafe
                                    try:
                                        return base64.b64decode(s)
                                    except Exception:
                                        return base64.urlsafe_b64decode(s)

                                ciphertext = decode_unpadded_base64(ciphertext_b64)
                                ephemeral_key = decode_unpadded_base64(ephemeral_b64)
                                mac = decode_unpadded_base64(mac_b64)

                                # 使用 ECDH + HKDF + HMAC + AES-CTR 解密
                                plaintext = _decrypt_backup_data(
                                    key_bytes, ephemeral_key, ciphertext, mac
                                )
                                if plaintext:
                                    logger.info(f"成功解密会话：{session_id[:8]}...")
                            except Exception as e:
                                logger.warning(f"备份解密失败：{e}")

                        if plaintext is None:
                            skipped += 1
                            continue

                        # 解析会话数据
                        try:
                            if isinstance(plaintext, bytes):
                                plaintext = plaintext.decode()
                            session_json = json.loads(plaintext)
                            session_key = session_json.get("session_key")

                            if session_key:
                                # 使用 OlmMachine 添加入站会话
                                self.olm.add_megolm_inbound_session(
                                    room_id, session_id, session_key, ""
                                )
                                restored += 1
                                logger.debug(
                                    f"恢复会话：room={room_id[:16]}... session={session_id[:8]}..."
                                )
                            else:
                                skipped += 1
                        except json.JSONDecodeError:
                            # 可能是 pickle 格式
                            self.store.save_megolm_inbound(session_id, plaintext)
                            restored += 1

                    except Exception as e:
                        logger.debug(f"恢复会话 {session_id[:8]}... 失败：{e}")
                        skipped += 1

            if restored > 0:
                logger.info(f"已恢复 {restored} 个会话密钥")
            if skipped > 0:
                logger.debug(f"跳过 {skipped} 个不兼容的会话")

        except Exception as e:
            logger.warning(f"恢复密钥失败：{e}")


class CrossSigning:
    """
    交叉签名管理器

    使用 vodozemac/ed25519 进行真正的签名操作
    """

    def __init__(
        self,
        client,
        user_id: str,
        device_id: str,
        olm_machine,
        password: str | None = None,
    ):
        self.client = client
        self.user_id = user_id
        self.device_id = device_id
        self.olm = olm_machine
        self.password = password

        self._master_key: str | None = None
        self._self_signing_key: str | None = None
        self._user_signing_key: str | None = None

        # 私钥（Raw 32B），仅本地持久化
        self._master_priv = None
        self._self_signing_priv = None
        self._user_signing_priv = None

        # 本地存储位置（与 E2EE store 同目录）
        try:
            self._storage_path = Path(self.olm.store.store_path) / "cross_signing.json"
        except Exception:
            self._storage_path = None

    async def initialize(self):
        """初始化交叉签名"""
        if not CRYPTO_AVAILABLE:
            logger.warning(
                "[E2EE-CrossSign] cryptography 不可用，无法生成/签名交叉签名密钥"
            )
            return

        try:
            self._load_local_keys()

            response = await self.client.query_keys({self.user_id: []})
            master_keys = response.get("master_keys", {}).get(self.user_id)
            self_keys = response.get("self_signing_keys", {}).get(self.user_id)
            user_keys = response.get("user_signing_keys", {}).get(self.user_id)

            server_master = None
            server_self_signing = None
            server_user_signing = None
            keys_need_regen = False

            if master_keys:
                keys = master_keys.get("keys", {})
                if keys:
                    # 获取 key ID 和公钥值
                    key_id = list(keys.keys())[0]
                    server_master = list(keys.values())[0]
                    self._master_key = server_master
                    logger.info("[E2EE-CrossSign] 发现服务器主密钥")

                    # 检测是否使用了错误的截断格式
                    # 正确格式：ed25519:<43 字符 base64 公钥>
                    # 错误格式：ed25519:<8 字符截断>
                    key_part = key_id.split(":", 1)[-1] if ":" in key_id else key_id
                    if len(key_part) < 20:  # 截断的 key ID 只有 8 个字符
                        logger.warning(
                            f"[E2EE-CrossSign] 检测到旧格式的 key ID (长度={len(key_part)})，需要重新生成"
                        )
                        keys_need_regen = True

            if self_keys:
                keys = self_keys.get("keys", {})
                if keys:
                    key_id = list(keys.keys())[0]
                    server_self_signing = list(keys.values())[0]
                    self._self_signing_key = server_self_signing
                    logger.info("[E2EE-CrossSign] 发现服务器自签名密钥")

                    key_part = key_id.split(":", 1)[-1] if ":" in key_id else key_id
                    if len(key_part) < 20:
                        logger.warning(
                            "[E2EE-CrossSign] 检测到旧格式的 self-signing key ID，需要重新生成"
                        )
                        keys_need_regen = True

            if user_keys:
                keys = user_keys.get("keys", {})
                if keys:
                    key_id = list(keys.keys())[0]
                    server_user_signing = list(keys.values())[0]
                    self._user_signing_key = server_user_signing
                    logger.info("[E2EE-CrossSign] 发现服务器用户签名密钥")

                    key_part = key_id.split(":", 1)[-1] if ":" in key_id else key_id
                    if len(key_part) < 20:
                        logger.warning(
                            "[E2EE-CrossSign] 检测到旧格式的 user-signing key ID，需要重新生成"
                        )
                        keys_need_regen = True

            # 如果检测到旧格式的 key ID，强制重新生成
            if keys_need_regen:
                logger.info("[E2EE-CrossSign] 正在重新生成交叉签名密钥以修复格式问题...")
                try:
                    await self._generate_and_upload_keys(force_regen=True)
                    return
                except Exception as e:
                    logger.error(f"[E2EE-CrossSign] 重新生成交叉签名密钥失败：{e}")
                    logger.warning("[E2EE-CrossSign] 将继续使用现有密钥（交叉签名可能无法正常工作）")

            # 如果服务器已有密钥但本地缺少私钥，尝试重新生成并覆盖
            if server_master and not self._master_priv:
                logger.warning(
                    "[E2EE-CrossSign] 服务器已有交叉签名密钥，但本地缺少私钥，正在尝试重新生成..."
                )
                try:
                    await self._generate_and_upload_keys(force_regen=True)
                    return
                except Exception as e:
                    logger.error(f"[E2EE-CrossSign] 重新生成交叉签名密钥失败：{e}")
                    logger.warning("[E2EE-CrossSign] 将继续使用服务器现有的密钥（但无法签名新设备）")
                    # 继续执行，不返回

            # 如缺少密钥则生成并上传
            if not server_master:
                try:
                    await self._generate_and_upload_keys()
                except Exception as e:
                    logger.error(f"[E2EE-CrossSign] 生成交叉签名密钥失败：{e}")
                    logger.warning("[E2EE-CrossSign] 交叉签名功能将不可用")
            elif server_master and server_self_signing and server_user_signing:
                logger.info("[E2EE-CrossSign] 交叉签名密钥已就绪")
                return
            elif server_master and self._master_priv:
                # 补全缺失的 self/user keys
                try:
                    await self._generate_and_upload_keys(
                        force_regen=False, reuse_master=True
                    )
                except Exception as e:
                    logger.error(f"[E2EE-CrossSign] 补全交叉签名密钥失败：{e}")
                    logger.warning("[E2EE-CrossSign] 部分交叉签名功能可能不可用")

        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] 初始化失败：{e}")

    def _b64(self, data: bytes) -> str:
        return base64.b64encode(data).decode().rstrip("=")

    def _canonical(self, obj: dict) -> str:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))

    def _load_local_keys(self):
        if not self._storage_path or not self._storage_path.exists():
            return
        try:
            data = json.loads(self._storage_path.read_text())
            for k, attr in [
                ("master", "_master_priv"),
                ("self_signing", "_self_signing_priv"),
                ("user_signing", "_user_signing_priv"),
            ]:
                if k in data and data[k].get("priv"):
                    # Add padding if missing
                    priv_str = data[k]["priv"]
                    padding = 4 - len(priv_str) % 4
                    if padding != 4:
                        priv_str += "=" * padding
                    setattr(self, attr, base64.b64decode(priv_str))

                if k in data and data[k].get("pub"):
                    pub_val = data[k]["pub"]
                    if k == "master":
                        self._master_key = pub_val
                    elif k == "self_signing":
                        self._self_signing_key = pub_val
                    elif k == "user_signing":
                        self._user_signing_key = pub_val
            logger.info("[E2EE-CrossSign] 已加载本地交叉签名密钥")
        except Exception:
            logger.warning("[E2EE-CrossSign] 读取本地交叉签名密钥失败，忽略并重新生成")

    def _save_local_keys(self):
        if not self._storage_path:
            return
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "master": {
                    "priv": self._b64(self._master_priv),
                    "pub": self._master_key,
                },
                "self_signing": {
                    "priv": self._b64(self._self_signing_priv),
                    "pub": self._self_signing_key,
                },
                "user_signing": {
                    "priv": self._b64(self._user_signing_priv),
                    "pub": self._user_signing_key,
                },
            }
            self._storage_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2)
            )
        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] 保存本地交叉签名密钥失败：{e}")

    def _gen_keypair(self) -> tuple[bytes, str]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        priv = Ed25519PrivateKey.generate()
        priv_raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv_raw, self._b64(pub_raw)

    def _sign(self, priv_raw: bytes, payload: dict) -> str:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
        msg = self._canonical(payload).encode()
        sig = priv.sign(msg)
        return self._b64(sig)

    async def _generate_and_upload_keys(
        self, force_regen: bool = False, reuse_master: bool = False, auth: dict = None
    ):
        """生成并上传交叉签名密钥，必要时复用本地主密钥"""

        if reuse_master and not self._master_priv:
            logger.warning("[E2EE-CrossSign] 无主密钥私钥，无法复用")
            return

        if force_regen or not self._master_priv:
            self._master_priv, self._master_key = self._gen_keypair()
        if force_regen or not self._self_signing_priv:
            self._self_signing_priv, self._self_signing_key = self._gen_keypair()
        if force_regen or not self._user_signing_priv:
            self._user_signing_priv, self._user_signing_key = self._gen_keypair()

        # Key ID 必须使用完整的公钥（Matrix 规范要求）
        # 格式：ed25519:<unpadded_base64_public_key>
        master_id = f"ed25519:{self._master_key}"
        self_id = f"ed25519:{self._self_signing_key}"
        user_id = f"ed25519:{self._user_signing_key}"

        master_key = {
            "user_id": self.user_id,
            "usage": ["master"],
            "keys": {master_id: self._master_key},
        }

        self_signing_key = {
            "user_id": self.user_id,
            "usage": ["self_signing"],
            "keys": {self_id: self._self_signing_key},
        }

        user_signing_key = {
            "user_id": self.user_id,
            "usage": ["user_signing"],
            "keys": {user_id: self._user_signing_key},
        }

        # master 签名 self/user key
        self_signing_key["signatures"] = {
            self.user_id: {master_id: self._sign(self._master_priv, self_signing_key)}
        }
        user_signing_key["signatures"] = {
            self.user_id: {master_id: self._sign(self._master_priv, user_signing_key)}
        }

        data = {
            "master_key": master_key,
            "self_signing_key": self_signing_key,
            "user_signing_key": user_signing_key,
        }
        if auth:
            data["auth"] = auth

        try:
            await self.client._request(
                "POST",
                "/_matrix/client/v3/keys/device_signing/upload",
                data=data,
            )
            self._save_local_keys()
            logger.info("[E2EE-CrossSign] 已生成并上传交叉签名密钥")

            # 验证上传结果
            logger.info("[E2EE-CrossSign] 正在验证交叉签名密钥上传结果...")
            verify_resp = await self.client.query_keys({self.user_id: []})

            # 检查 master key
            master_on_server = verify_resp.get("master_keys", {}).get(self.user_id, {})
            if master_on_server:
                mk_id = list(master_on_server.get("keys", {}).keys())[0] if master_on_server.get("keys") else "N/A"
                mk_val = list(master_on_server.get("keys", {}).values())[0] if master_on_server.get("keys") else "N/A"
                logger.info(f"[E2EE-CrossSign] 服务器 master key ID：{mk_id}")
                logger.info(f"[E2EE-CrossSign] 服务器 master 公钥：{mk_val[:20]}..." if mk_val != "N/A" else "[E2EE-CrossSign] 服务器 master 公钥：N/A")

            # 检查 self-signing key
            ssk_on_server = verify_resp.get("self_signing_keys", {}).get(self.user_id, {})
            if ssk_on_server:
                ssk_id = list(ssk_on_server.get("keys", {}).keys())[0] if ssk_on_server.get("keys") else "N/A"
                ssk_val = list(ssk_on_server.get("keys", {}).values())[0] if ssk_on_server.get("keys") else "N/A"
                ssk_sigs = ssk_on_server.get("signatures", {}).get(self.user_id, {})
                logger.info(f"[E2EE-CrossSign] 服务器 self-signing key ID：{ssk_id}")
                logger.info(f"[E2EE-CrossSign] self-signing key 的签名：{list(ssk_sigs.keys())}")
            else:
                logger.warning("[E2EE-CrossSign] 服务器未返回 self-signing key！")
        except MatrixAPIError as e:
            # Check for UIA (User Interactive Authentication) or 401
            if e.status == 401 and isinstance(e.data, dict):
                flows = e.data.get("flows", [])
                session = e.data.get("session")

                # Check for password flow
                password_flow = next((f for f in flows if "m.login.password" in f.get("stages", [])), None)

                if password_flow and self.password and session and not auth:
                    logger.info("[E2EE-CrossSign] Received UIA challenge, attempting password auth...")

                    auth_data = {
                        "type": "m.login.password",
                        "identifier": {
                            "type": "m.id.user",
                            "user": self.user_id
                        },
                        "password": self.password,
                        "session": session
                    }

                    try:
                        await self._generate_and_upload_keys(
                            force_regen=force_regen,
                            reuse_master=reuse_master,
                            auth=auth_data
                        )
                        return
                    except Exception as inner_e:
                        logger.error(f"[E2EE-CrossSign] UIA authentication failed: {inner_e}")
                        raise

            msg = str(e)
            if "status: 401" in msg or "401" in msg:
                logger.warning(
                    "[E2EE-CrossSign] 上传交叉签名密钥失败：服务器要求认证 (401)"
                )
                logger.warning(f"错误详情：{msg}")
                logger.warning("这通常意味着需要用户交互式认证 (UIA) 来重置密钥。")
                logger.warning("由于当前无法进行交互式认证（或密码不可用），将跳过密钥上传。")
                logger.warning("⚠️ 注意：本地交叉签名私钥未保存，且与服务器不匹配。")
                # Do NOT save local keys to avoid persisting invalid state
                return
            else:
                logger.error(f"[E2EE-CrossSign] 上传交叉签名密钥失败：{e}")
                raise e
        except Exception as e:
            logger.error(f"[E2EE-CrossSign] 上传交叉签名密钥失败：{e}")
            raise e

    async def upload_cross_signing_keys(self):
        """上传交叉签名密钥"""
        if not CRYPTO_AVAILABLE:
            logger.error("[E2EE-CrossSign] 缺少 cryptography，无法上传交叉签名密钥")
            return
        await self._generate_and_upload_keys(force_regen=False)

    async def sign_device(self, device_id: str):
        """签名自己的设备"""
        if not self._self_signing_key or not self._self_signing_priv:
            logger.warning("[E2EE-CrossSign] 未设置自签名密钥或私钥")
            return

        try:
            response = await self.client.query_keys({self.user_id: [device_id]})
            device_keys = response.get("device_keys", {}).get(self.user_id, {})

            if device_id not in device_keys:
                logger.warning(f"[E2EE-CrossSign] 未找到设备：{device_id}")
                return

            device_key = device_keys[device_id]
            logger.debug(f"[E2EE-CrossSign] 准备签名设备密钥：{list(device_key.get('keys', {}).keys())}")

            # 构造要签名的对象（不包含 signatures 和 unsigned）
            # Matrix 规范要求签名的是不包含 signatures 的对象
            key_to_sign = {
                "user_id": device_key.get("user_id"),
                "device_id": device_key.get("device_id"),
                "algorithms": device_key.get("algorithms"),
                "keys": device_key.get("keys"),
            }

            # 使用 self-signing 私钥签名
            signature = self._sign(self._self_signing_priv, key_to_sign)

            # 构造签名 key ID - 使用完整的 self-signing 公钥
            sign_key_id = f"ed25519:{self._self_signing_key}"
            logger.info(f"[E2EE-CrossSign] 使用 self-signing key 签名：{sign_key_id[:40]}...")

            # 根据 Matrix 规范，上传签名需要包含完整的设备密钥对象
            # 添加新的签名到现有签名中
            existing_signatures = device_key.get("signatures", {}).copy()
            if self.user_id not in existing_signatures:
                existing_signatures[self.user_id] = {}
            existing_signatures[self.user_id][sign_key_id] = signature

            # 构造完整的上传对象
            signed_device_key = {
                "user_id": device_key.get("user_id"),
                "device_id": device_key.get("device_id"),
                "algorithms": device_key.get("algorithms"),
                "keys": device_key.get("keys"),
                "signatures": existing_signatures,
            }

            upload_data = {
                self.user_id: {
                    device_id: signed_device_key,
                }
            }
            logger.debug(f"[E2EE-CrossSign] 上传签名数据：用户={self.user_id}, 设备={device_id}")
            logger.debug(f"[E2EE-CrossSign] 签名列表：{list(existing_signatures.get(self.user_id, {}).keys())}")

            resp = await self.client._request(
                "POST",
                "/_matrix/client/v3/keys/signatures/upload",
                data=upload_data,
            )

            # 检查响应
            logger.info(f"[E2EE-CrossSign] 签名上传响应：{resp}")

            # 检查是否有失败
            failures = resp.get("failures", {})
            if failures:
                logger.error(f"[E2EE-CrossSign] 签名上传失败：{failures}")
            else:
                logger.info(f"[E2EE-CrossSign] 已成功签名设备：{device_id}")

                # 验证签名是否真的在服务器上
                verify_resp = await self.client.query_keys({self.user_id: [device_id]})
                verify_device = verify_resp.get("device_keys", {}).get(self.user_id, {}).get(device_id, {})
                verify_sigs = verify_device.get("signatures", {}).get(self.user_id, {})
                logger.info(f"[E2EE-CrossSign] 验证后的签名列表：{list(verify_sigs.keys())}")

                # 检查交叉签名是否存在
                if sign_key_id in verify_sigs:
                    logger.info(f"[E2EE-CrossSign] ✅ 交叉签名已成功添加到服务器")
                else:
                    logger.error(f"[E2EE-CrossSign] ❌ 交叉签名未出现在服务器上！")
                    logger.error(f"[E2EE-CrossSign] 期望的签名 key ID：{sign_key_id}")
                    logger.error(f"[E2EE-CrossSign] 实际的签名列表：{verify_sigs}")

                # 额外验证：查询交叉签名密钥状态
                logger.info("[E2EE-CrossSign] 正在验证交叉签名密钥状态...")
                cross_keys = verify_resp.get("self_signing_keys", {}).get(self.user_id, {})
                if cross_keys:
                    cross_key_id = list(cross_keys.get("keys", {}).keys())[0] if cross_keys.get("keys") else "N/A"
                    cross_key_val = list(cross_keys.get("keys", {}).values())[0] if cross_keys.get("keys") else "N/A"
                    logger.info(f"[E2EE-CrossSign] 服务器上的 self-signing key ID：{cross_key_id}")
                    logger.info(f"[E2EE-CrossSign] 服务器上的 self-signing 公钥：{cross_key_val}")
                    logger.info(f"[E2EE-CrossSign] 本地的 self-signing 公钥：{self._self_signing_key}")
                    if cross_key_val == self._self_signing_key:
                        logger.info("[E2EE-CrossSign] ✅ self-signing 公钥匹配")
                    else:
                        logger.error("[E2EE-CrossSign] ❌ self-signing 公钥不匹配！")
                else:
                    logger.warning("[E2EE-CrossSign] 服务器未返回 self-signing key")

        except Exception as e:
            import traceback
            logger.error(f"[E2EE-CrossSign] 签名设备失败：{e}")
            logger.error(f"[E2EE-CrossSign] 详情：{traceback.format_exc()}")

    async def verify_user(self, target_user_id: str):
        """验证其他用户（使用 user-signing key 签名其 master key）"""
        if not self._user_signing_key or not self._user_signing_priv:
            logger.warning("[E2EE-CrossSign] 未设置用户签名密钥或私钥")
            return

        try:
            response = await self.client.query_keys({target_user_id: []})
            master_keys = response.get("master_keys", {})

            if target_user_id not in master_keys:
                logger.warning(f"[E2EE-CrossSign] 未找到用户主密钥：{target_user_id}")
                return

            master_key = master_keys[target_user_id]
            key_id = list(master_key.get("keys", {}).keys())[0]

            # 构造要签名的对象（不包含 signatures）
            key_to_sign = {
                "user_id": master_key.get("user_id"),
                "usage": master_key.get("usage"),
                "keys": master_key.get("keys"),
            }

            signature = self._sign(self._user_signing_priv, key_to_sign)
            # 使用完整的 user-signing 公钥作为 key ID
            sign_key_id = f"ed25519:{self._user_signing_key}"

            # 构造完整的上传对象（包含签名的 master key）
            existing_signatures = master_key.get("signatures", {}).copy()
            if self.user_id not in existing_signatures:
                existing_signatures[self.user_id] = {}
            existing_signatures[self.user_id][sign_key_id] = signature

            signed_master_key = {
                "user_id": master_key.get("user_id"),
                "usage": master_key.get("usage"),
                "keys": master_key.get("keys"),
                "signatures": existing_signatures,
            }

            # Matrix spec: /keys/signatures/upload 格式为 {user_id: {key_id: signed_object}}
            upload_data = {
                target_user_id: {
                    key_id.split(":")[-1]: signed_master_key,  # key_id 去掉 ed25519: 前缀
                }
            }

            await self.client._request(
                "POST",
                "/_matrix/client/v3/keys/signatures/upload",
                data=upload_data,
            )

            logger.info(f"[E2EE-CrossSign] 已验证用户：{target_user_id}")

        except Exception as e:
            import traceback
            logger.error(f"[E2EE-CrossSign] 验证用户失败：{e}")
            logger.error(f"[E2EE-CrossSign] 详情：{traceback.format_exc()}")

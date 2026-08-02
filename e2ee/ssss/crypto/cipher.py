"""Secret Storage AES-CTR/HMAC encryption helpers."""

import secrets

from astrbot.api import logger

from ....constants import CRYPTO_KEY_SIZE_32
from ...backup.crypto_utils import (
    _aes_ctr_decrypt,
    _compute_hkdf,
)
from ...verification.crypto_utils import _decode_base64, _encode_unpadded_base64
from .compat import _DEFAULT_CRYPTO_AVAILABLE, crypto_available


class KeyBackupSSSSCipherMixin:
    """Matrix Secret Storage AES-CTR 与 HMAC-SHA-256 加解密。"""

    def _encrypt_ssss_data(
        self,
        key: bytes,
        plaintext: bytes,
        secret_name: str = "",
        iv: bytes | None = None,
    ) -> dict[str, str]:
        if not crypto_available(_DEFAULT_CRYPTO_AVAILABLE):
            raise RuntimeError("缺少 cryptography 库，无法进行 SSSS 加密")

        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives import hmac as crypto_hmac
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except Exception as e:
            raise RuntimeError(f"cryptography 不可用，无法执行 SSSS 加密：{e}") from e

        if not key or len(key) != CRYPTO_KEY_SIZE_32:
            raise ValueError("SSSS key 必须是 32 字节")

        if iv is None:
            iv_bytes = bytearray(secrets.token_bytes(16))
            iv_bytes[8] &= 0x7F
            iv = bytes(iv_bytes)
        elif len(iv) != 16:
            raise ValueError("SSSS IV 必须是 16 字节")

        info = secret_name.encode("utf-8") if secret_name else b""
        salt = b"\x00" * CRYPTO_KEY_SIZE_32
        derived = _compute_hkdf(key, salt, info, length=64)
        aes_key = derived[:CRYPTO_KEY_SIZE_32]
        hmac_key = derived[CRYPTO_KEY_SIZE_32:64]

        cipher = Cipher(
            algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        h = crypto_hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(ciphertext)
        mac = h.finalize()

        return {
            "ciphertext": _encode_unpadded_base64(ciphertext),
            "iv": _encode_unpadded_base64(iv),
            "mac": _encode_unpadded_base64(mac),
        }

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
            ciphertext = _decode_base64(ciphertext_b64)
            iv = _decode_base64(iv_b64)
            mac = _decode_base64(mac_b64)
        except Exception:
            return None

        if not crypto_available(_DEFAULT_CRYPTO_AVAILABLE):
            logger.error("缺少 cryptography 库，无法进行 SSSS 解密")
            return None

        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives import hmac as crypto_hmac
        except Exception:
            logger.error("cryptography 不可用，无法验证 SSSS MAC")
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

"""Secret Storage AES-CTR/HMAC encryption."""

import secrets

from .....constants import CRYPTO_KEY_SIZE_32
from ....backup.crypto_utils import _compute_hkdf
from ....verification.crypto_utils import _encode_unpadded_base64
from ..compat import _DEFAULT_CRYPTO_AVAILABLE, crypto_available


class KeyBackupSSSSCipherEncryptionMixin:
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

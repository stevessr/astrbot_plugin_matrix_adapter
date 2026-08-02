"""Symmetric primitives used by Matrix key-backup compatibility paths."""

import secrets

from ....constants import AES_GCM_NONCE_LEN
from . import AESGCM as _DEFAULT_AESGCM
from . import CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE
from . import default_backend as _DEFAULT_DEFAULT_BACKEND
from .compat import crypto_available, resolve_attribute


def _aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """AES-GCM 加密"""
    nonce = secrets.token_bytes(AES_GCM_NONCE_LEN)
    if crypto_available(_DEFAULT_CRYPTO_AVAILABLE):
        aesgcm_cls = resolve_attribute("AESGCM", _DEFAULT_AESGCM)
        aesgcm = aesgcm_cls(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    else:
        # 简化实现 (不安全，仅用于测试)
        ciphertext = bytes(
            a ^ b for a, b in zip(plaintext, key * (len(plaintext) // len(key) + 1))
        )
    return nonce, ciphertext


def _aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """AES-GCM 解密"""
    if crypto_available(_DEFAULT_CRYPTO_AVAILABLE):
        aesgcm_cls = resolve_attribute("AESGCM", _DEFAULT_AESGCM)
        aesgcm = aesgcm_cls(key)
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
    if crypto_available(_DEFAULT_CRYPTO_AVAILABLE):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        backend_factory = resolve_attribute(
            "default_backend",
            _DEFAULT_DEFAULT_BACKEND,
        )
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend_factory())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    else:
        # 无法使用简化实现，因为 CTR 模式需要正确的计数器处理
        raise RuntimeError("需要 cryptography 库来解密密钥备份")

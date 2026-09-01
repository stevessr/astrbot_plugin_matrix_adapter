"""Utilities for decrypting Matrix encrypted media (stable v1.19 schema)."""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any


def _decode_unpadded_base64(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("Empty base64 value")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        try:
            return base64.b64decode(padded, validate=True)
        except Exception as exc:
            raise ValueError("Invalid base64 value") from exc


def _validate_encrypted_file_info(
    file_info: dict[str, Any],
) -> tuple[bytes, bytes, bytes]:
    """Validate the Matrix v1.19 ``EncryptedFile`` structure.

    Returns ``(key, iv, expected_sha256)`` only after all stable required
    fields and fixed algorithm parameters have been checked.
    """
    if not isinstance(file_info, dict):
        raise ValueError("Invalid encrypted file info")

    url = file_info.get("url")
    if not isinstance(url, str) or not url.startswith("mxc://"):
        raise ValueError("Encrypted file is missing a valid mxc:// url")

    if file_info.get("v") != "v2":
        raise ValueError("Encrypted file version must be v2")

    key_info = file_info.get("key")
    if not isinstance(key_info, dict):
        raise ValueError("Encrypted file is missing JWK key metadata")
    if key_info.get("kty") != "oct":
        raise ValueError("Encrypted file JWK kty must be oct")
    if key_info.get("alg") != "A256CTR":
        raise ValueError("Encrypted file JWK alg must be A256CTR")
    if key_info.get("ext") is not True:
        raise ValueError("Encrypted file JWK ext must be true")

    key_ops = key_info.get("key_ops")
    if not isinstance(key_ops, list) or not {"encrypt", "decrypt"}.issubset(
        {value for value in key_ops if isinstance(value, str)}
    ):
        raise ValueError(
            "Encrypted file JWK key_ops must contain encrypt and decrypt"
        )

    key_b64 = key_info.get("k")
    iv_b64 = file_info.get("iv")
    hashes = file_info.get("hashes")
    if not isinstance(hashes, dict):
        raise ValueError("Encrypted file is missing hashes")
    expected_hash_b64 = hashes.get("sha256")
    if not isinstance(expected_hash_b64, str) or not expected_hash_b64:
        raise ValueError("Encrypted file is missing hashes.sha256")

    key = _decode_unpadded_base64(key_b64)
    iv = _decode_unpadded_base64(iv_b64)
    expected_hash = _decode_unpadded_base64(expected_hash_b64)
    if len(key) != 32:
        raise ValueError("Encrypted file A256CTR key must be 32 bytes")
    if len(iv) != 16:
        raise ValueError("Encrypted file AES-CTR iv must be 16 bytes")
    if len(expected_hash) != 32:
        raise ValueError("Encrypted file sha256 must be 32 bytes")

    return key, iv, expected_hash


def decrypt_encrypted_file(file_info: dict[str, Any], ciphertext: bytes) -> bytes:
    """Validate, authenticate, and decrypt a Matrix encrypted attachment."""
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")

    key, iv, expected_hash = _validate_encrypted_file_info(file_info)
    actual_hash = hashlib.sha256(ciphertext).digest()
    if not hmac.compare_digest(actual_hash, expected_hash):
        raise ValueError("Encrypted file sha256 mismatch")

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("cryptography is required to decrypt Matrix media") from exc

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


__all__ = ["decrypt_encrypted_file"]

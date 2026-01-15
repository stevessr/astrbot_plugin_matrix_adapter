"""Utilities for decrypting Matrix encrypted media (v1.17 spec)."""

from __future__ import annotations

import base64
import hashlib
from typing import Any


def _decode_unpadded_base64(value: str) -> bytes:
    if not value:
        raise ValueError("Empty base64 value")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return base64.b64decode(padded)


def decrypt_encrypted_file(file_info: dict[str, Any], ciphertext: bytes) -> bytes:
    """Decrypt Matrix encrypted file payload.

    Expects a file_info dict with keys: url, key, iv, hashes, v.
    """
    if not isinstance(file_info, dict):
        raise ValueError("Invalid encrypted file info")

    version = file_info.get("v")
    if version and version != "v2":
        raise ValueError(f"Unsupported encrypted file version: {version}")

    key_info = file_info.get("key") or {}
    if key_info.get("kty") != "oct":
        raise ValueError("Unsupported key type for encrypted file")

    key_b64 = key_info.get("k")
    iv_b64 = file_info.get("iv")
    if not key_b64 or not iv_b64:
        raise ValueError("Missing key or iv for encrypted file")

    key = _decode_unpadded_base64(key_b64)
    iv = _decode_unpadded_base64(iv_b64)

    hashes = file_info.get("hashes") or {}
    expected_hash = hashes.get("sha256")
    if expected_hash:
        expected = _decode_unpadded_base64(expected_hash)
        actual = hashlib.sha256(ciphertext).digest()
        if actual != expected:
            raise ValueError("Encrypted file sha256 mismatch")

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("cryptography is required to decrypt Matrix media") from exc

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

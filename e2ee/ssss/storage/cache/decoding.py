"""Decode Secret Storage key payloads returned by account-data decryption."""

from .....constants import CRYPTO_KEY_SIZE_32
from ....verification.crypto_utils import _decode_base64


class KeyBackupSSSSStorageCacheDecodingMixin:
    def _decode_secret_storage_key_payload(self, payload: bytes) -> bytes | None:
        if not payload:
            return None

        if len(payload) == CRYPTO_KEY_SIZE_32:
            return payload

        try:
            secret_str = payload.decode("utf-8").strip()
        except Exception:
            return None

        if not secret_str:
            return None

        try:
            decoded = _decode_base64(secret_str)
        except Exception:
            return None

        if len(decoded) == CRYPTO_KEY_SIZE_32:
            return decoded
        return None

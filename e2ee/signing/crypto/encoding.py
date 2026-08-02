"""Encoding and Ed25519 key derivation helpers for cross-signing."""

import base64
import json


class CrossSigningCryptoEncodingMixin:
    """base64、canonical JSON、密钥解码与 Ed25519 密钥派生。"""

    def _b64(self, data: bytes) -> str:
        return base64.b64encode(data).decode().rstrip("=")

    def _b64_optional(self, data: bytes | None) -> str | None:
        if data is None:
            return None
        return self._b64(data)

    def _canonical(self, obj: dict) -> str:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )

    def _decode_secret_bytes(self, secret_bytes: bytes) -> bytes | None:
        if not secret_bytes:
            return None
        if len(secret_bytes) == 32:
            return secret_bytes
        try:
            secret_str = secret_bytes.decode("utf-8").strip()
        except Exception:
            return None
        if not secret_str:
            return None
        padding = "=" * (-len(secret_str) % 4)
        try:
            decoded = base64.b64decode(secret_str + padding)
        except Exception:
            return None
        if len(decoded) == 32:
            return decoded
        return None

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

    def _derive_public_key(self, priv_raw: bytes) -> str | None:
        """从私钥推导出公钥（unpadded base64）"""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
            pub_raw = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return self._b64(pub_raw)
        except Exception:
            return None

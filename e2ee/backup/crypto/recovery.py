"""Recovery-key verification against Matrix backup versions."""

import base64

from astrbot.api import logger

from ....constants import CRYPTO_KEY_SIZE_32


class KeyBackupCryptoRecoveryMixin:
    """验证恢复密钥是否匹配当前备份公钥。"""

    def _verify_recovery_key(self, key_bytes: bytes, log_mismatch: bool = True) -> bool:
        """验证恢复密钥是否与当前备份匹配"""
        key_len = len(key_bytes) if key_bytes else 0
        if key_len != CRYPTO_KEY_SIZE_32:
            if log_mismatch:
                logger.warning(f"恢复密钥长度无效：期望 32 字节，实际 {key_len} 字节")
            else:
                logger.debug("恢复密钥长度无效（静默模式）")
            return False

        if not self._backup_auth_data:
            return True  # 无法验证，假设正确

        try:
            expected_public_key = self._backup_auth_data.get("public_key")
            if not expected_public_key:
                return True

            # Always use cryptography for verification to generate consistent Public Key
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
                if log_mismatch:
                    logger.warning("恢复密钥不匹配当前备份版本公钥")
                    logger.debug(f"备份版本要求公钥：{expected_public_key}")
                    logger.debug(
                        f"当前密钥生成公钥：{public_key_std} (或 {public_key})"
                    )
                else:
                    logger.debug("恢复密钥与备份公钥不匹配（静默模式）")
                return False

            logger.info("✅ 恢复密钥与备份版本公钥匹配")
            logger.debug(f"备份版本公钥：{expected_public_key}")
            return True

        except Exception as e:
            logger.warning(f"验证密钥失败：{e}")
            import traceback

            logger.warning(traceback.format_exc())
            return False

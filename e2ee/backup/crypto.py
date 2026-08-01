import base64
import hashlib
import hmac

from astrbot.api import logger

from ...constants import (
    AES_GCM_NONCE_LEN,
    CRYPTO_KEY_SIZE_32,
    MEGOLM_ALGO,
    RECOVERY_KEY_MAC_TRUNCATED_LEN,
)
from ..megolm.inbound import _convert_session_key_v2_to_v1
from .crypto_utils import (
    _aes_decrypt,
    _aes_encrypt,
    _encrypt_backup_data,
)


class KeyBackupBackupCryptoMixin:
    @staticmethod
    def _decode_unpadded_base64(data: str) -> bytes:
        padding = (-len(data)) % 4
        if padding:
            data += "=" * padding
        try:
            return base64.b64decode(data)
        except Exception:
            return base64.urlsafe_b64decode(data)

    def _get_backup_public_key_bytes(self) -> bytes | None:
        backup_auth_data = getattr(self, "_backup_auth_data", None)
        public_key = backup_auth_data.get("public_key") if backup_auth_data else None
        if not public_key:
            return None

        try:
            key_bytes = self._decode_unpadded_base64(public_key)
        except Exception as e:
            logger.warning(f"解析备份公钥失败：{e}")
            return None

        if len(key_bytes) != CRYPTO_KEY_SIZE_32:
            logger.warning(
                f"备份公钥长度无效：期望 {CRYPTO_KEY_SIZE_32} 字节，实际 {len(key_bytes)} 字节"
            )
            return None
        return key_bytes

    def _build_encrypted_session_data(self, plaintext: bytes) -> dict:
        backup_public_key = self._get_backup_public_key_bytes()
        if backup_public_key:
            ephemeral_key, ciphertext, mac = _encrypt_backup_data(
                backup_public_key, plaintext
            )
            return {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "mac": base64.b64encode(mac).decode(),
                "ephemeral": base64.b64encode(ephemeral_key).decode().rstrip("="),
            }

        logger.warning("备份版本缺少有效 public_key，回退到旧版 AES-GCM 备份格式")
        nonce, ciphertext = _aes_encrypt(self._encryption_key, plaintext)
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "mac": base64.b64encode(
                hmac.new(self._encryption_key, ciphertext, hashlib.sha256).digest()[
                    :RECOVERY_KEY_MAC_TRUNCATED_LEN
                ]
            ).decode(),
            "ephemeral": base64.b64encode(nonce).decode(),
        }

    @staticmethod
    def _build_backed_up_session_data(
        session_key: str,
        *,
        sender_key: str = "",
        sender_claimed_keys: dict[str, str] | None = None,
        forwarding_curve25519_key_chain: list[str] | None = None,
        shared_history: bool = False,
    ) -> dict:
        """Build the plaintext ``BackedUpSessionData`` structure."""
        claimed_keys = sender_claimed_keys or {}
        forwarding_chain = forwarding_curve25519_key_chain or []
        return {
            "algorithm": MEGOLM_ALGO,
            "forwarding_curve25519_key_chain": [
                key for key in forwarding_chain if isinstance(key, str)
            ],
            "sender_claimed_keys": {
                str(algorithm): key
                for algorithm, key in claimed_keys.items()
                if isinstance(key, str)
            },
            "sender_key": sender_key if isinstance(sender_key, str) else "",
            "session_key": _convert_session_key_v2_to_v1(session_key),
            "shared_history": shared_history is True,
        }

    def _decrypt_legacy_backup_data(
        self,
        ciphertext: bytes,
        ephemeral_key: bytes,
        mac: bytes,
    ) -> bytes | None:
        if len(ephemeral_key) != AES_GCM_NONCE_LEN:
            logger.warning(
                f"未知旧版备份 nonce 长度：期望 {AES_GCM_NONCE_LEN} 字节，实际 {len(ephemeral_key)} 字节"
            )
            return None

        expected_mac = hmac.new(
            self._encryption_key, ciphertext, hashlib.sha256
        ).digest()[:RECOVERY_KEY_MAC_TRUNCATED_LEN]
        if mac != expected_mac:
            logger.warning("旧版备份 MAC 校验失败，跳过该会话")
            return None

        logger.info("检测到旧版 AES-GCM 备份格式，使用兼容逻辑恢复会话")
        return _aes_decrypt(self._encryption_key, ephemeral_key, ciphertext)

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

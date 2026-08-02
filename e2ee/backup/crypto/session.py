"""Session payload encryption and legacy backup decryption helpers."""

import base64
import hashlib
import hmac

from astrbot.api import logger

from ....constants import (
    AES_GCM_NONCE_LEN,
    MEGOLM_ALGO,
    RECOVERY_KEY_MAC_TRUNCATED_LEN,
)
from ...megolm.inbound import _convert_session_key_v2_to_v1
from ..crypto_utils import (
    _aes_decrypt,
    _aes_encrypt,
    _encrypt_backup_data,
)


class KeyBackupCryptoSessionMixin:
    """构造备份会话数据并兼容旧 AES-GCM 格式。"""

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

"""Single-session decryption and import from a key-backup snapshot."""

import json

from astrbot.api import logger

from .....constants import AES_GCM_NONCE_LEN, CRYPTO_KEY_SIZE_32
from ...crypto_utils import _decrypt_backup_data as _DEFAULT_DECRYPT_BACKUP_DATA
from ..compat import resolve_restore_symbol


class KeyBackupRoomKeysRestoreSessionMixin:
    """Decrypt and import a single backed-up Megolm session."""

    async def _restore_single_session(
        self, room_id: str, session_id: str, session_data: dict, key_bytes: bytes
    ) -> bool:
        """Decrypt and import one backed-up session; return True on success."""
        encrypted_data = session_data.get("session_data", {})
        # 获取加密数据
        ciphertext_b64 = encrypted_data.get("ciphertext", "")
        ephemeral_b64 = encrypted_data.get("ephemeral", "")
        mac_b64 = encrypted_data.get("mac", "")

        if not ciphertext_b64:
            logger.warning(f"会话 {(session_id or '')[:8]}... 无 ciphertext")
            return False

        plaintext = None

        # 尝试使用 Matrix 标准备份解密 (m.megolm_backup.v1.curve25519-aes-sha2)
        if ephemeral_b64 and mac_b64:
            try:
                ciphertext = self._decode_unpadded_base64(ciphertext_b64)
                ephemeral_key = self._decode_unpadded_base64(ephemeral_b64)
                mac = self._decode_unpadded_base64(mac_b64)

                if len(ephemeral_key) == CRYPTO_KEY_SIZE_32:
                    decrypt_backup_data = resolve_restore_symbol(
                        "_decrypt_backup_data",
                        _DEFAULT_DECRYPT_BACKUP_DATA,
                    )
                    plaintext = decrypt_backup_data(
                        key_bytes, ephemeral_key, ciphertext, mac
                    )
                elif len(ephemeral_key) == AES_GCM_NONCE_LEN:
                    plaintext = self._decrypt_legacy_backup_data(
                        ciphertext, ephemeral_key, mac
                    )
                else:
                    logger.warning(
                        f"备份会话 {(session_id or '')[:8]}... 的 ephemeral 长度无效：{len(ephemeral_key)}"
                    )
            except Exception as e:
                logger.warning(f"备份解密失败：{e}")

        if plaintext is None:
            return False

        # 解析会话数据
        try:
            if isinstance(plaintext, bytes):
                plaintext = plaintext.decode()
            session_json = json.loads(plaintext)
            session_key = session_json.get("session_key")

            if session_key:
                # 使用 OlmMachine 添加入站会话
                imported = self.olm.add_megolm_inbound_session(
                    room_id,
                    session_id,
                    session_key,
                    session_json.get("sender_key", ""),
                    sender_claimed_keys=session_json.get("sender_claimed_keys"),
                    forwarding_curve25519_key_chain=session_json.get(
                        "forwarding_curve25519_key_chain"
                    ),
                    shared_history=(session_json.get("shared_history") is True),
                )
                if imported:
                    return True
                else:
                    return False
            else:
                return False
        except json.JSONDecodeError:
            # 非 JSON 格式，可能已损坏或不兼容
            logger.warning(f"会话 {session_id[:8]} 数据不是 JSON 格式，跳过")
            return False

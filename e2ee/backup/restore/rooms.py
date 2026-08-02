"""Room-session restoration from Matrix key backups."""

import json
import time

from astrbot.api import logger

from ....constants import AES_GCM_NONCE_LEN, CRYPTO_KEY_SIZE_32
from ..crypto_utils import (
    VODOZEMAC_PK_AVAILABLE as _DEFAULT_VODOZEMAC_PK_AVAILABLE,
)
from ..crypto_utils import (
    Curve25519SecretKey as _DEFAULT_CURVE25519_SECRET_KEY,
)
from ..crypto_utils import (
    PkDecryption as _DEFAULT_PK_DECRYPTION,
)
from ..crypto_utils import (
    _decode_recovery_key as _DEFAULT_DECODE_RECOVERY_KEY,
)
from ..crypto_utils import (
    _decrypt_backup_data as _DEFAULT_DECRYPT_BACKUP_DATA,
)
from .compat import resolve_restore_symbol


class KeyBackupRoomKeysRestoreMixin:
    """从密钥备份恢复房间会话。"""

    async def restore_room_keys(self, recovery_key: str | None = None) -> bool:
        """
        从备份恢复密钥

        Args:
            recovery_key: 恢复密钥 (覆盖初始化时的密钥)
        """
        if not self._backup_version:
            logger.warning("未发现备份，无法恢复")
            return False

        # 确定使用的恢复密钥
        key_bytes = None
        if recovery_key:
            try:
                decode_recovery_key = resolve_restore_symbol(
                    "_decode_recovery_key", _DEFAULT_DECODE_RECOVERY_KEY
                )
                key_bytes = decode_recovery_key(recovery_key)
            except Exception as e:
                logger.error(f"解析恢复密钥失败：{e}")
                return False
        elif self._recovery_key_bytes:
            key_bytes = self._recovery_key_bytes
        else:
            logger.error("无恢复密钥，无法解密备份")
            return False

        self._last_restore_attempt_ts = time.monotonic()

        # 验证密钥是否匹配备份版本
        if not self._verify_recovery_key(key_bytes):
            return False

        # Keep using the verified key for subsequent runs.
        self.use_recovery_key_bytes(key_bytes, persist=True)

        # 创建 PkDecryption 对象 (如果 vodozemac 可用)
        _pk_decryption = None
        if resolve_restore_symbol(
            "VODOZEMAC_PK_AVAILABLE", _DEFAULT_VODOZEMAC_PK_AVAILABLE
        ):
            try:
                # key_bytes 需要转换为 Curve25519SecretKey 对象
                secret_key_cls = resolve_restore_symbol(
                    "Curve25519SecretKey", _DEFAULT_CURVE25519_SECRET_KEY
                )
                pk_decryption_cls = resolve_restore_symbol(
                    "PkDecryption", _DEFAULT_PK_DECRYPTION
                )
                secret_key = secret_key_cls.from_bytes(key_bytes)
                _pk_decryption = pk_decryption_cls.from_key(secret_key)
                logger.debug("使用 vodozemac PkDecryption 解密备份")
            except Exception as e:
                logger.warning(f"创建 PkDecryption 失败：{e}")

        try:
            logger.info(f"开始从备份恢复密钥 (version={self._backup_version})")
            response = await self.client.get_room_keys(self._backup_version)

            rooms = response.get("rooms", {})
            total_sessions = sum(len(s) for s in rooms.values())
            logger.info(f"获取到 {len(rooms)} 个房间，共 {total_sessions} 个会话")

            restored = 0
            skipped = 0

            for room_id, room_data in rooms.items():
                # API 返回格式：rooms[room_id] = {"sessions": {session_id: {...}}}
                sessions = room_data.get("sessions", room_data)
                if not isinstance(sessions, dict):
                    sessions = room_data  # 回退到直接使用 room_data
                for session_id, session_data in sessions.items():
                    try:
                        encrypted_data = session_data.get("session_data", {})
                        # 记录数据结构以便调试
                        # 获取加密数据
                        ciphertext_b64 = encrypted_data.get("ciphertext", "")
                        ephemeral_b64 = encrypted_data.get("ephemeral", "")
                        mac_b64 = encrypted_data.get("mac", "")

                        if not ciphertext_b64:
                            logger.warning(
                                f"会话 {(session_id or '')[:8]}... 无 ciphertext"
                            )
                            skipped += 1
                            continue

                        plaintext = None

                        # 尝试使用 Matrix 标准备份解密 (m.megolm_backup.v1.curve25519-aes-sha2)
                        if ephemeral_b64 and mac_b64:
                            try:
                                ciphertext = self._decode_unpadded_base64(
                                    ciphertext_b64
                                )
                                ephemeral_key = self._decode_unpadded_base64(
                                    ephemeral_b64
                                )
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
                            skipped += 1
                            continue

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
                                    sender_claimed_keys=session_json.get(
                                        "sender_claimed_keys"
                                    ),
                                    forwarding_curve25519_key_chain=session_json.get(
                                        "forwarding_curve25519_key_chain"
                                    ),
                                    shared_history=(
                                        session_json.get("shared_history") is True
                                    ),
                                )
                                if imported:
                                    restored += 1
                                else:
                                    skipped += 1
                            else:
                                skipped += 1
                        except json.JSONDecodeError:
                            # 非 JSON 格式，可能已损坏或不兼容
                            logger.warning(
                                f"会话 {session_id[:8]} 数据不是 JSON 格式，跳过"
                            )
                            skipped += 1

                    except Exception as e:
                        logger.debug(f"恢复会话 {(session_id or '')[:8]}... 失败：{e}")
                        skipped += 1

            if restored > 0:
                logger.info(f"已恢复 {restored} 个会话密钥")
            if skipped > 0:
                logger.debug(f"跳过 {skipped} 个不兼容的会话")
            return restored > 0

        except Exception as e:
            logger.warning(f"恢复密钥失败：{e}")
            return False

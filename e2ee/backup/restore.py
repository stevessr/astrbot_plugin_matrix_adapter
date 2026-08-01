import json
import time

from astrbot.api import logger

from ...constants import (
    AES_GCM_NONCE_LEN,
    CRYPTO_KEY_SIZE_32,
)
from .crypto_utils import (
    VODOZEMAC_PK_AVAILABLE,
    Curve25519SecretKey,
    PkDecryption,
    _decode_recovery_key,
    _decrypt_backup_data,
)


class KeyBackupBackupRestoreMixin:
    async def initialize(self):
        """初始化密钥备份"""
        try:
            version = await self._get_current_backup_version()
            if version:
                self._backup_version = version
                # 1) Prefer already-verified local backup key material.
                local_key = self._get_valid_local_recovery_key_bytes()
                if local_key:
                    if self.use_recovery_key_bytes(local_key):
                        logger.info("✅ 使用本地保存的提取密钥成功验证！")
                        return

                # 2) Treat configured key as dehydrated/backup recovery material first,
                # then fall back to Secret Storage compatibility.
                provided_key = getattr(
                    self,
                    "_provided_recovery_material_bytes",
                    self._provided_secret_storage_key_bytes,
                )
                if provided_key:
                    real_key = await self._try_restore_from_dehydrated_device_key(
                        provided_key
                    )
                    if real_key and self._verify_recovery_key(
                        real_key, log_mismatch=False
                    ):
                        if self.use_recovery_key_bytes(real_key, persist=True):
                            logger.info(
                                "✅ 已通过配置密钥解出 dehydrated device 中的备份密钥"
                            )
                            return

                    # 3) Fallback: configured key is direct backup key.
                    if self._verify_recovery_key(provided_key, log_mismatch=False):
                        if self.use_recovery_key_bytes(provided_key):
                            logger.info("✅ 提供密钥可直接作为备份恢复密钥")
                            return

                    # 4) Compatibility fallback: configured key may still be a Secret Storage key.
                    real_key = await self._try_restore_from_secret_storage(
                        provided_key,
                        include_dehydrated=False,
                        allow_local_short_circuit=False,
                    )
                    if real_key and self._verify_recovery_key(
                        real_key, log_mismatch=False
                    ):
                        if self.use_recovery_key_bytes(real_key, persist=True):
                            logger.info(
                                "✅ 已通过配置密钥兼容解出 Secret Storage 中的备份密钥"
                            )
                            return

                    logger.warning(
                        "配置密钥未能匹配当前备份，等待后续 secret.send/手动更新"
                    )
                elif self._recovery_key_bytes and self._verify_recovery_key(
                    self._recovery_key_bytes, log_mismatch=False
                ):
                    self.use_recovery_key_bytes(self._recovery_key_bytes)
            else:
                logger.info("未发现密钥备份")
        except Exception as e:
            logger.warning(f"初始化失败：{e}")

    def should_restore_for_session(
        self, session_id: str | None = None, force: bool = False
    ) -> bool:
        """Whether backup restoration should run for current account state."""
        if force:
            return self.can_attempt_restore()

        if not self.can_attempt_restore():
            return False

        # This account already has keys: skip restore by default.
        if self.has_local_room_keys():
            return False

        # If a specific session already exists locally, skip.
        if session_id and self.store.has_megolm_inbound(session_id):
            return False

        now = time.monotonic()
        if now - self._last_restore_attempt_ts < self._restore_cooldown_sec:
            return False
        return True

    async def restore_room_keys_if_needed(
        self,
        session_id: str | None = None,
        reason: str = "runtime",
        force: bool = False,
    ) -> bool:
        """Restore keys from backup only when account key state requires it."""
        if not self.should_restore_for_session(session_id=session_id, force=force):
            logger.debug(f"跳过备份恢复：reason={reason} session={session_id or '-'}")
            return False
        return await self.restore_room_keys()

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
                key_bytes = _decode_recovery_key(recovery_key)
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
        if VODOZEMAC_PK_AVAILABLE:
            try:
                # key_bytes 需要转换为 Curve25519SecretKey 对象
                secret_key = Curve25519SecretKey.from_bytes(key_bytes)
                _pk_decryption = PkDecryption.from_key(secret_key)
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
                                    plaintext = _decrypt_backup_data(
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

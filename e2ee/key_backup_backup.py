import base64
import hashlib
import hmac
import json
import secrets
import time

from astrbot.api import logger

from ..constants import (
    CRYPTO_KEY_SIZE_32,
    MEGOLM_BACKUP_ALGO,
    RECOVERY_KEY_MAC_TRUNCATED_LEN,
)
from .key_backup_crypto import (
    VODOZEMAC_PK_AVAILABLE,
    Curve25519SecretKey,
    PkDecryption,
    _aes_encrypt,
    _compute_hkdf,
    _decode_recovery_key,
    _decrypt_backup_data,
    _encode_recovery_key,
)


class KeyBackupBackupMixin:
    async def initialize(self):
        """初始化密钥备份"""
        try:
            version = await self._get_current_backup_version()
            if version:
                self._backup_version = version
                # 1) Prefer previously extracted real backup key.
                extracted_key = self._load_extracted_key()
                if extracted_key and self._verify_recovery_key(
                    extracted_key, log_mismatch=False
                ):
                    if self.use_recovery_key_bytes(extracted_key):
                        logger.info("✅ 使用本地保存的提取密钥成功验证！")
                        return

                # 2) Treat configured key as Secret Storage Key by default.
                provided_key = self._provided_secret_storage_key_bytes
                if provided_key:
                    real_key = await self._try_restore_from_secret_storage(provided_key)
                    if real_key and self._verify_recovery_key(
                        real_key, log_mismatch=False
                    ):
                        if self.use_recovery_key_bytes(real_key, persist=True):
                            logger.info(
                                "✅ 已通过 Secret Storage Key 获取并验证备份密钥"
                            )
                            return

                    # 3) Fallback: configured key is direct backup key.
                    if self._verify_recovery_key(provided_key, log_mismatch=False):
                        if self.use_recovery_key_bytes(provided_key):
                            logger.info("✅ 提供密钥可直接作为备份恢复密钥")
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

    async def _get_current_backup_version(self) -> str | None:
        """获取当前备份版本"""
        try:
            response = await self.client._request(
                "GET", "/_matrix/client/v3/room_keys/version"
            )
            version = response.get("version")
            if version:
                self._backup_auth_data = response.get("auth_data", {})
            return version
        except Exception:
            return None

    def _verify_recovery_key(
        self, key_bytes: bytes, log_mismatch: bool = True
    ) -> bool:
        """验证恢复密钥是否与当前备份匹配"""
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
                    logger.warning(f"备份版本要求公钥：{expected_public_key}")
                    logger.warning(
                        f"当前密钥生成公钥：{public_key_std} (或 {public_key})"
                    )
                else:
                    logger.debug("恢复密钥与备份公钥不匹配（静默模式）")
                return False

            logger.info(f"✅ 恢复密钥与备份版本公钥匹配 ({expected_public_key})")
            return True

        except Exception as e:
            logger.warning(f"验证密钥失败：{e}")
            import traceback

            logger.warning(traceback.format_exc())
            return True

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

    async def create_backup(self) -> tuple[str, str] | None:
        """
        创建新的密钥备份

        Returns:
            (version, recovery_key) 或 None
        """
        try:
            # 如果没有提供恢复密钥，生成新的
            if not self._recovery_key_bytes:
                self._recovery_key_bytes = secrets.token_bytes(CRYPTO_KEY_SIZE_32)
                self._encryption_key = _compute_hkdf(
                    self._recovery_key_bytes, b"", b"m.megolm_backup.v1"
                )
                recovery_key_str = _encode_recovery_key(self._recovery_key_bytes)

                logger.warning("" + "=" * 50)
                logger.warning("⚠️  新生成的恢复密钥（请务必保存）:")
                logger.warning(f"{recovery_key_str}")
                logger.warning("可将此密钥配置到 matrix_e2ee_recovery_key")
                logger.warning("" + "=" * 50)
            else:
                recovery_key_str = _encode_recovery_key(self._recovery_key_bytes)

            # 生成用于备份的公钥
            # 根据 Matrix 规范，使用 X25519 从私钥派生公钥
            # 参考：https://spec.matrix.org/latest/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import x25519

            private_key = x25519.X25519PrivateKey.from_private_bytes(
                self._recovery_key_bytes
            )
            public_key_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            # 使用 unpadded base64 编码
            public_key = base64.b64encode(public_key_bytes).decode().rstrip("=")

            # 创建备份
            response = await self.client._request(
                "POST",
                "/_matrix/client/v3/room_keys/version",
                data={
                    "algorithm": MEGOLM_BACKUP_ALGO,
                    "auth_data": {
                        "public_key": public_key,
                    },
                },
            )

            version = response.get("version")
            if version:
                self._backup_version = version
                logger.info(f"创建备份成功：version={version}")
                return (version, recovery_key_str)

        except Exception as e:
            logger.error(f"创建备份失败：{e}")
        return None

    async def upload_room_keys(self, room_id: str | None = None):
        """
        上传房间密钥到备份

        Args:
            room_id: 可选，指定房间 ID
        """
        if not self._backup_version or not self._encryption_key:
            logger.warning("未创建备份或无加密密钥，无法上传")
            return

        try:
            sessions = self.store._megolm_inbound
            if not sessions:
                logger.debug("没有可上传的会话密钥")
                return

            rooms: dict[str, dict[str, dict]] = {}

            for session_id, pickle in sessions.items():
                # 加密会话数据
                plaintext = pickle.encode() if isinstance(pickle, str) else pickle
                nonce, ciphertext = _aes_encrypt(self._encryption_key, plaintext)

                session_data = {
                    "first_message_index": 0,
                    "forwarded_count": 0,
                    "is_verified": True,
                    "session_data": {
                        "ciphertext": base64.b64encode(ciphertext).decode(),
                        "mac": base64.b64encode(
                            hmac.new(
                                self._encryption_key, ciphertext, hashlib.sha256
                            ).digest()[:RECOVERY_KEY_MAC_TRUNCATED_LEN]
                        ).decode(),
                        "ephemeral": base64.b64encode(nonce).decode(),
                    },
                }

                target_room = room_id or "unknown"
                if target_room not in rooms:
                    rooms[target_room] = {}
                rooms[target_room][session_id] = session_data

            await self.client._request(
                "PUT",
                f"/_matrix/client/v3/room_keys/keys?version={self._backup_version}",
                data={"rooms": rooms},
            )

            logger.info(f"已上传 {len(sessions)} 个会话密钥")

        except Exception as e:
            logger.error(f"上传密钥失败：{e}")

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
            response = await self.client._request(
                "GET",
                f"/_matrix/client/v3/room_keys/keys?version={self._backup_version}",
            )

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
                            logger.warning(f"会话 {session_id[:8]}... 无 ciphertext")
                            skipped += 1
                            continue

                        plaintext = None

                        # 尝试使用 Matrix 标准备份解密 (m.megolm_backup.v1.curve25519-aes-sha2)
                        if ephemeral_b64 and mac_b64:
                            try:
                                # Matrix 使用无填充的 base64url 编码
                                def decode_unpadded_base64(s: str) -> bytes:
                                    # 添加缺失的填充
                                    padding = 4 - len(s) % 4
                                    if padding != 4:
                                        s += "=" * padding
                                    # 尝试标准 base64，然后 urlsafe
                                    try:
                                        return base64.b64decode(s)
                                    except Exception:
                                        return base64.urlsafe_b64decode(s)

                                ciphertext = decode_unpadded_base64(ciphertext_b64)
                                ephemeral_key = decode_unpadded_base64(ephemeral_b64)
                                mac = decode_unpadded_base64(mac_b64)

                                # 使用 ECDH + HKDF + HMAC + AES-CTR 解密
                                plaintext = _decrypt_backup_data(
                                    key_bytes, ephemeral_key, ciphertext, mac
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
                                self.olm.add_megolm_inbound_session(
                                    room_id, session_id, session_key, ""
                                )
                                restored += 1
                            else:
                                skipped += 1
                        except json.JSONDecodeError:
                            # 可能是 pickle 格式
                            self.store.save_megolm_inbound(session_id, plaintext)
                            restored += 1

                    except Exception as e:
                        logger.debug(f"恢复会话 {session_id[:8]}... 失败：{e}")
                        skipped += 1

            if restored > 0:
                logger.info(f"已恢复 {restored} 个会话密钥")
            if skipped > 0:
                logger.debug(f"跳过 {skipped} 个不兼容的会话")
            return restored > 0

        except Exception as e:
            logger.warning(f"恢复密钥失败：{e}")
            return False

    async def upload_single_key(
        self,
        room_id: str,
        session_id: str,
        session_key: str,
        algorithm: str = MEGOLM_BACKUP_ALGO,
    ) -> bool:
        """
        上传当个会话密钥到备份

        Args:
            room_id: 房间 ID
            session_id: 会话 ID
            session_key: 会话密钥
            algorithm: 算法 (默认 m.megolm_backup.v1.curve25519-aes-sha2)

        Returns:
            bool: 是否成功
        """
        if not self._backup_version or not self._encryption_key:
            return False

        try:
            # 加密会话数据
            plaintext = session_key.encode()
            nonce, ciphertext = _aes_encrypt(self._encryption_key, plaintext)

            session_data = {
                "first_message_index": 0,
                "forwarded_count": 0,
                "is_verified": True,
                "session_data": {
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "mac": base64.b64encode(
                        hmac.new(
                            self._encryption_key, ciphertext, hashlib.sha256
                        ).digest()[:RECOVERY_KEY_MAC_TRUNCATED_LEN]
                    ).decode(),
                    "ephemeral": base64.b64encode(nonce).decode(),
                },
            }

            await self.client._request(
                "PUT",
                f"/_matrix/client/v3/room_keys/keys/{room_id}/{session_id}?version={self._backup_version}",
                data=session_data,
            )
            return True

        except Exception as e:
            logger.warning(f"[KeyBackup] 备份单个密钥失败：{e}")
            return False

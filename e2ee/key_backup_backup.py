import base64
import hashlib
import hmac
import json
import secrets
import time

from astrbot.api import logger

from ..constants import (
    AES_GCM_NONCE_LEN,
    CRYPTO_KEY_SIZE_32,
    MEGOLM_ALGO,
    MEGOLM_BACKUP_ALGO,
    RECOVERY_KEY_MAC_TRUNCATED_LEN,
)
from .key_backup_crypto import (
    VODOZEMAC_PK_AVAILABLE,
    Curve25519SecretKey,
    PkDecryption,
    _aes_decrypt,
    _aes_encrypt,
    _compute_hkdf,
    _decode_recovery_key,
    _decrypt_backup_data,
    _encode_recovery_key,
    _encrypt_backup_data,
)
from .olm_machine_megolm import _convert_session_key_v2_to_v1


class KeyBackupBackupMixin:
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

    async def _get_current_backup_version(self) -> str | None:
        """获取当前备份版本"""
        try:
            response = await self.client.get_key_backup_versions()
            version = response.get("version")
            if version:
                self._backup_auth_data = response.get("auth_data", {})
            return version
        except Exception:
            return None

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
                logger.warning("已生成新的恢复密钥。出于安全考虑，密钥不会写入日志。")
                logger.warning(
                    "请从安全输出通道复制返回值并配置到 matrix_e2ee_recovery_key。"
                )
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
            response = await self.client.create_key_backup_version(
                {
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
        if not self._backup_version:
            logger.warning("未创建备份，无法上传")
            return

        try:
            session_ids = list(self.store._megolm_inbound)
            if not session_ids:
                logger.debug("没有可上传的会话密钥")
                return

            rooms: dict[str, dict[str, dict]] = {}
            uploaded = 0

            for session_id in session_ids:
                metadata = self.store.get_megolm_inbound_metadata(session_id) or {}
                target_room = room_id or metadata.get("room_id")
                if not isinstance(target_room, str) or not target_room:
                    logger.debug(
                        f"跳过缺少 room_id 的会话：{(session_id or '')[:8]}..."
                    )
                    continue
                if room_id and metadata.get("room_id") not in (None, room_id):
                    continue

                session = self.olm.get_megolm_inbound_session(session_id)
                if not session:
                    continue
                first_message_index = self.olm.get_megolm_first_known_index(session)
                exported_key = session.export_at(first_message_index).to_base64()
                backed_up_session = self._build_backed_up_session_data(
                    exported_key,
                    sender_key=metadata.get("sender_key", ""),
                    sender_claimed_keys=metadata.get("sender_claimed_keys"),
                    forwarding_curve25519_key_chain=metadata.get(
                        "forwarding_curve25519_key_chain"
                    ),
                    shared_history=metadata.get("shared_history") is True,
                )
                plaintext = json.dumps(
                    backed_up_session,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()

                session_data = {
                    "first_message_index": first_message_index,
                    "forwarded_count": len(
                        backed_up_session["forwarding_curve25519_key_chain"]
                    ),
                    "is_verified": True,
                    "session_data": self._build_encrypted_session_data(plaintext),
                }

                room_sessions = rooms.setdefault(target_room, {"sessions": {}})
                room_sessions["sessions"][session_id] = session_data
                uploaded += 1

            if not uploaded:
                logger.debug("没有可上传的完整会话数据")
                return

            await self.client.store_room_keys(
                self._backup_version,
                {"rooms": rooms},
            )

            logger.info(f"已上传 {uploaded} 个会话密钥")

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
                            logger.warning(f"会话 {session_id[:8]} 数据不是 JSON 格式，跳过")
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

    async def upload_single_key(
        self,
        room_id: str,
        session_id: str,
        session_key: str,
        algorithm: str = MEGOLM_ALGO,
        *,
        sender_key: str = "",
        sender_claimed_keys: dict[str, str] | None = None,
        forwarding_curve25519_key_chain: list[str] | None = None,
        shared_history: bool = False,
    ) -> bool:
        """
        上传当个会话密钥到备份

        Args:
            room_id: 房间 ID
            session_id: 会话 ID
            session_key: 会话密钥
            algorithm: 会话算法（仅支持 m.megolm.v1.aes-sha2）
            sender_key: 创建会话的设备 Curve25519 密钥
            sender_claimed_keys: 创建设备声明的签名密钥
            forwarding_curve25519_key_chain: 会话密钥转发链
            shared_history: Matrix v1.19 会话可共享标记

        Returns:
            bool: 是否成功
        """
        if not self._backup_version:
            return False
        if algorithm != MEGOLM_ALGO:
            logger.warning(f"[KeyBackup] 不支持的会话算法：{algorithm}")
            return False

        try:
            backed_up_session = self._build_backed_up_session_data(
                session_key,
                sender_key=sender_key,
                sender_claimed_keys=sender_claimed_keys,
                forwarding_curve25519_key_chain=forwarding_curve25519_key_chain,
                shared_history=shared_history,
            )
            plaintext = json.dumps(
                backed_up_session,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            forwarding_count = len(backed_up_session["forwarding_curve25519_key_chain"])
            session_data = {
                "first_message_index": 0,
                "forwarded_count": forwarding_count,
                "is_verified": True,
                "session_data": self._build_encrypted_session_data(plaintext),
            }

            try:
                await self.client.store_room_key_for_session(
                    self._backup_version,
                    room_id,
                    session_id,
                    session_data,
                )
                return True
            except Exception as e:
                errcode = None
                if isinstance(getattr(e, "data", None), dict):
                    errcode = e.data.get("errcode")
                if getattr(e, "status", None) != 404 or errcode != "M_UNRECOGNIZED":
                    raise

                logger.info(
                    "[KeyBackup] 单会话备份接口未识别，回退到批量 room_keys 接口"
                )
                await self.client.store_room_keys(
                    self._backup_version,
                    {
                        "rooms": {
                            room_id: {
                                "sessions": {
                                    session_id: session_data,
                                }
                            }
                        }
                    },
                )
                return True

        except Exception as e:
            logger.warning(f"[KeyBackup] 备份单个密钥失败：{e}")
            return False

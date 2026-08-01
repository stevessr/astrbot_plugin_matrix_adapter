import base64
import json
import secrets

from astrbot.api import logger

from ...constants import (
    CRYPTO_KEY_SIZE_32,
    MEGOLM_ALGO,
    MEGOLM_BACKUP_ALGO,
)
from .crypto_utils import (
    _compute_hkdf,
    _encode_recovery_key,
)


class KeyBackupBackupUploadMixin:
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
            session_ids = list(self.store.get_megolm_inbound_ids())
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

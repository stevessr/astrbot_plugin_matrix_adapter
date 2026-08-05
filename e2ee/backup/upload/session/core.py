"""Single-room-session upload orchestration."""

import json

from astrbot.api import logger

from .....constants import MEGOLM_ALGO


class KeyBackupUploadSessionOrchestratorMixin:
    """上传单个房间会话密钥并处理接口回退。"""

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
        if not self._check_upload_guard(algorithm):
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

            await self._upload_session_with_fallback(
                room_id,
                session_id,
                session_data,
            )
            return True

        except Exception as e:
            logger.warning(f"[KeyBackup] 备份单个密钥失败：{e}")
            return False


__all__ = ["KeyBackupUploadSessionOrchestratorMixin"]

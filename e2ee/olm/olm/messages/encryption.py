"""Olm message encryption and Matrix envelope construction."""

import base64
import json

from astrbot.api import logger

from .....constants import M_ROOM_KEY, OLM_ALGO
from ...types import Session


class OlmMachineMessageEncryptionMixin:
    def encrypt_olm(
        self,
        their_identity_key: str,
        content: dict,
        session: Session | None = None,
        recipient_user_id: str = "unknown",
        recipient_ed25519_key: str = "unknown",
        event_type: str = M_ROOM_KEY,
    ) -> dict:
        masked_identity_key = (their_identity_key or "")[:8]
        """
        使用 Olm 加密内容并添加 Matrix 协议外壳

        Args:
            their_identity_key: 对方的 curve25519 密钥
            content: 要加密的内容 (m.room_key 等)
            session: 可选，已有的 Olm 会话
            recipient_user_id: 接收者用户 ID
            recipient_ed25519_key: 接收者的 ed25519 密钥
            event_type: 事件类型（默认 m.room_key）

        Returns:
            符合 m.room.encrypted (Olm) 格式的字典
        """
        session_index: int | None = None
        if not session:
            # 尝试使用现有会话
            sessions = self._olm_sessions.get(their_identity_key, [])
            if sessions:
                session_index = len(sessions) - 1
                session = sessions[session_index]
                logger.debug(f"使用现有 Olm 会话对 {masked_identity_key}... 加密")
            else:
                logger.warning(f"没有可用于 {masked_identity_key}... 的 Olm 会话")
                raise RuntimeError(f"没有可用于 {their_identity_key} 的 Olm 会话")
        else:
            sessions = self._olm_sessions.get(their_identity_key, [])
            if sessions:
                for idx, existing in enumerate(sessions):
                    if existing is session:
                        session_index = idx
                        break
                if session_index is None:
                    session_index = len(sessions) - 1

        # 构造 Matrix 协议外壳
        wrapper = {
            "sender": self.user_id,
            "sender_device": self.device_id,
            "keys": {"ed25519": self.ed25519_key},
            # Matrix v1.15+ (MSC4147): carrying the signed device object lets
            # the receiver validate the sender without a racy /keys/query.
            "sender_device_keys": self.get_device_keys(),
            "recipient": recipient_user_id,
            "recipient_keys": {"ed25519": recipient_ed25519_key},
            "type": event_type,
            "content": content,
        }

        # 加密
        payload_json = json.dumps(wrapper, ensure_ascii=False)
        ciphertext = session.encrypt(payload_json.encode())

        # vodozemac 返回 AnyOlmMessage，需要使用 to_parts() 获取消息类型和密文
        # to_parts() 返回 (message_type: int, ciphertext: bytes)
        message_type, ciphertext_bytes = ciphertext.to_parts()

        # 将密文转换为 base64 字符串
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode()

        logger.debug(
            f"Olm 加密完成：type={message_type} payload_len={len(payload_json)}"
        )

        # 更新存储
        if session_index is not None and session_index >= 0:
            self.store.update_olm_session(
                their_identity_key,
                session_index,
                session.pickle(self._pickle_key),
            )

        return {
            "algorithm": OLM_ALGO,
            "sender_key": self.curve25519_key,
            "ciphertext": {
                their_identity_key: {
                    "type": message_type,
                    "body": ciphertext_b64,
                }
            },
        }

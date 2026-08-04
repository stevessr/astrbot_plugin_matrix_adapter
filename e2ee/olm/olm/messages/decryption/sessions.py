"""Decrypt with existing inbound sessions, keeping the freshest last."""

from astrbot.api import logger

from ....types import AnyOlmMessage


class OlmMachineMessageDecryptionSessionsMixin:
    def _decrypt_with_existing_sessions(
        self,
        sender_key: str,
        message_type: int,
        ciphertext_bytes: bytes,
    ) -> str | None:
        sessions = self._olm_sessions.get(sender_key, [])
        for i in range(len(sessions) - 1, -1, -1):
            session = sessions[i]
            try:
                # 使用 AnyOlmMessage.from_parts 创建消息对象
                message = AnyOlmMessage.from_parts(message_type, ciphertext_bytes)
                plaintext = session.decrypt(message)
                logger.debug(f"使用现有会话 {i} 解密成功")
                # Matrix selects the session which most recently received a
                # valid message. Keep that session last for outgoing traffic.
                if i != len(sessions) - 1:
                    sessions.append(sessions.pop(i))
                replace_sessions = getattr(
                    self.store,
                    "replace_olm_sessions",
                    None,
                )
                if callable(replace_sessions):
                    replace_sessions(
                        sender_key,
                        [item.pickle(self._pickle_key) for item in sessions],
                    )
                else:
                    self.store.update_olm_session(
                        sender_key,
                        len(sessions) - 1,
                        session.pickle(self._pickle_key),
                    )
                return plaintext
            except Exception as e:
                logger.debug(f"会话 {i} 解密失败：{e}")
                continue
        return None

import json

from astrbot.api import logger

from ...constants import MEGOLM_MESSAGE_INDEX_FIELD
from ...olm.types import InboundGroupSession, MegolmMessage


class OlmMachineMegolmInboundDecryptionMixin:
    @staticmethod
    def get_megolm_first_known_index(session) -> int:
        """Return a Megolm session index across supported vodozemac versions."""
        value = session.first_known_index
        value = value() if callable(value) else value
        if type(value) is not int or value < 0:
            raise ValueError("Invalid Megolm first-known index")
        return value

    def decrypt_megolm(self, session_id: str, ciphertext: str) -> dict | None:
        """
        解密 Megolm 消息

        Args:
            session_id: 会话 ID
            ciphertext: 密文

        Returns:
            解密后的事件内容，或 None
        """
        # 尝试从缓存获取会话
        session = self._megolm_inbound.get(session_id)

        # 尝试从存储加载 vodozemac session
        if not session:
            pickle = self.store.get_megolm_inbound(session_id)
            if pickle:
                try:
                    session = InboundGroupSession.from_pickle(pickle, self._pickle_key)
                    self._megolm_inbound[session_id] = session
                except Exception as e:
                    logger.error(f"加载 Megolm 会话失败：{e}")
                    return None

        if not session:
            logger.warning(f"未找到 Megolm 会话：{(session_id or '')[:8]}...")
            return None

        try:
            # Convert ciphertext string to MegolmMessage
            if isinstance(ciphertext, str):
                message = MegolmMessage.from_base64(ciphertext)
            else:
                message = ciphertext
            plaintext = session.decrypt(message)
            # 解析解密后的 JSON
            decrypted = json.loads(plaintext.plaintext)
            if not isinstance(decrypted, dict):
                logger.warning("Megolm plaintext is not a JSON object")
                return None
            decrypted[MEGOLM_MESSAGE_INDEX_FIELD] = plaintext.message_index
            return decrypted
        except Exception as e:
            logger.error(f"Megolm 解密失败：{e}")
            return None

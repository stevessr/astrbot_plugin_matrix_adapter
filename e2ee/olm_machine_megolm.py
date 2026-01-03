import json

from astrbot.api import logger

from ..constants import MEGOLM_ALGO
from .olm_machine_types import (
    ExportedSessionKey,
    GroupSession,
    InboundGroupSession,
    MegolmMessage,
)


class OlmMachineMegolmMixin:
    def add_megolm_inbound_session(
        self, room_id: str, session_id: str, session_key: str, sender_key: str
    ):
        """
        添加 Megolm 入站会话 (从 m.room_key 事件或备份恢复)

        Args:
            room_id: 房间 ID
            session_id: 会话 ID
            session_key: 会话密钥 (base64 编码的字符串)
            sender_key: 发送者的 curve25519 密钥
        """
        try:
            # vodozemac ExportedSessionKey constructor accepts base64 strings
            # Matrix key backups store exported session keys (starting with "AQ")
            if isinstance(session_key, str):
                # Use ExportedSessionKey constructor which implements from_base64
                exported_key = ExportedSessionKey(session_key)
                session = InboundGroupSession.import_session(exported_key)
                self._megolm_inbound[session_id] = session
                self.store.save_megolm_inbound(
                    session_id, session.pickle(self._pickle_key)
                )
                logger.info(
                    f"添加 Megolm 入站会话：{session_id[:8]}... 房间：{room_id}"
                )
            else:
                # vodozemac SessionKey object (from m.room_key events)
                session = InboundGroupSession(session_key)
                self._megolm_inbound[session_id] = session
                self.store.save_megolm_inbound(
                    session_id, session.pickle(self._pickle_key)
                )
                logger.debug(
                    f"添加 Megolm 入站会话：{session_id[:8]}... 房间：{room_id}"
                )
        except Exception as e:
            logger.error(f"添加 Megolm 入站会话失败：{e}")

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
            logger.warning(f"未找到 Megolm 会话：{session_id[:8]}...")
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
            # 调试：记录解密后的完整内容
            logger.debug(
                f"[OlmMachine] Megolm 解密成功，type={decrypted.get('type')}, "
                f"content keys={list(decrypted.get('content', {}).keys())}"
            )
            return decrypted
        except Exception as e:
            logger.error(f"Megolm 解密失败：{e}")
            return None

    def get_megolm_inbound_session(self, session_id: str):
        """
        获取 Megolm 入站会话对象（用于导出会话密钥等操作）

        Args:
            session_id: 会话 ID

        Returns:
            InboundGroupSession 或 None
        """
        # 先从缓存获取
        session = self._megolm_inbound.get(session_id)
        if session:
            return session

        # 尝试从存储加载
        pickle = self.store.get_megolm_inbound(session_id)
        if pickle:
            try:
                session = InboundGroupSession.from_pickle(pickle, self._pickle_key)
                self._megolm_inbound[session_id] = session
                return session
            except Exception as e:
                logger.error(f"加载 Megolm 会话失败：{e}")
                return None

        return None

    def create_megolm_outbound_session(self, room_id: str) -> tuple[str, str]:
        """
        创建 Megolm 出站会话

        Args:
            room_id: 房间 ID

        Returns:
            (session_id, session_key_base64) 元组
        """
        session = GroupSession()
        self._megolm_outbound[room_id] = session
        self.store.save_megolm_outbound(room_id, session.pickle(self._pickle_key))

        return session.session_id, session.session_key.to_base64()

    def encrypt_megolm(self, room_id: str, event_type: str, content: dict) -> dict:
        """
        使用 Megolm 加密消息

        Args:
            room_id: 房间 ID
            event_type: 事件类型
            content: 事件内容

        Returns:
            加密后的 m.room.encrypted 内容
        """
        session = self._megolm_outbound.get(room_id)
        if not session:
            # Try to load from store
            pickle = self.store.get_megolm_outbound(room_id)
            if pickle:
                try:
                    session = GroupSession.from_pickle(pickle, self._pickle_key)
                    self._megolm_outbound[room_id] = session
                except Exception as e:
                    logger.error(f"加载 Megolm 出站会话失败：{e}")

        if not session:
            raise RuntimeError(f"房间 {room_id} 没有 Megolm 出站会话")

        # 构造要加密的有效载荷
        payload = {
            "type": event_type,
            "content": content,
            "room_id": room_id,
        }
        payload_json = json.dumps(payload, ensure_ascii=False)

        # 加密
        ciphertext = session.encrypt(payload_json.encode())

        # 更新存储
        self.store.save_megolm_outbound(room_id, session.pickle(self._pickle_key))

        return {
            "algorithm": MEGOLM_ALGO,
            "sender_key": self._account.curve25519_key.to_base64()
            if self._account
            else "",
            "session_id": session.session_id,
            "ciphertext": ciphertext.to_base64(),
            "device_id": self.device_id,
        }

    # ========== 辅助方法 ==========

import base64
import json

from astrbot.api import logger

from ..constants import MEGOLM_ALGO
from .olm_machine_types import (
    ExportedSessionKey,
    GroupSession,
    InboundGroupSession,
    MegolmMessage,
)


def _convert_session_key_v2_to_v1(session_key_b64: str) -> str:
    """
    将 SessionKey 格式（版本 2）转换为 ExportedSessionKey 格式（版本 1）

    m.room_key 事件中的 session_key 使用版本 2 格式（以 "Ag" 开头），
    但 vodozemac 的 ExportedSessionKey 只接受版本 1 格式（以 "AQ" 开头）。
    两者的区别只是第一个字节（版本号）不同，其余数据相同。
    """
    # 添加 base64 填充
    padded = session_key_b64 + "=" * (-len(session_key_b64) % 4)
    raw = base64.b64decode(padded)

    if raw[0] == 2:
        # 版本 2 -> 版本 1
        modified = bytes([1]) + raw[1:]
        return base64.b64encode(modified).decode().rstrip("=")
    else:
        # 已经是版本 1 或其他格式，直接返回
        return session_key_b64


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
            if isinstance(session_key, str):
                # 尝试转换版本 2 格式到版本 1 格式
                # m.room_key 事件使用版本 2，ExportedSessionKey 需要版本 1
                converted_key = _convert_session_key_v2_to_v1(session_key)
                exported_key = ExportedSessionKey(converted_key)
                session = InboundGroupSession.import_session(exported_key)
                self._megolm_inbound[session_id] = session
                self.store.save_megolm_inbound(
                    session_id, session.pickle(self._pickle_key)
                )
                logger.debug(f"添加 Megolm 入站会话成功：{session_id[:8]}...")
            else:
                # vodozemac SessionKey object (from m.room_key events)
                session = InboundGroupSession(session_key)
                self._megolm_inbound[session_id] = session
                self.store.save_megolm_inbound(
                    session_id, session.pickle(self._pickle_key)
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

        session_id = session.session_id
        session_key = session.session_key

        # 同时创建入站会话，以便能解密自己发送的消息
        try:
            inbound_session = InboundGroupSession(session_key)
            self._megolm_inbound[session_id] = inbound_session
            self.store.save_megolm_inbound(
                session_id, inbound_session.pickle(self._pickle_key)
            )
            logger.debug(f"为自己创建了入站会话：{session_id[:8]}...")
        except Exception as e:
            logger.warning(f"创建自己的入站会话失败：{e}")

        return session_id, session_key.to_base64()

    def get_megolm_outbound_session_info(self, room_id: str) -> tuple[str, str] | None:
        """
        获取现有 Megolm 出站会话的信息（不创建新会话）

        Args:
            room_id: 房间 ID

        Returns:
            (session_id, session_key_base64) 元组，如果会话不存在则返回 None
        """
        session = self._megolm_outbound.get(room_id)
        if not session:
            # 尝试从存储加载
            pickle = self.store.get_megolm_outbound(room_id)
            if pickle:
                try:
                    session = GroupSession.from_pickle(pickle, self._pickle_key)
                    self._megolm_outbound[room_id] = session
                except Exception as e:
                    logger.error(f"加载 Megolm 出站会话失败：{e}")
                    return None

        if session:
            session_id = session.session_id
            session_key = session.session_key

            # 确保对应的入站会话存在，以便能解密自己发送的消息
            if session_id not in self._megolm_inbound:
                inbound_pickle = self.store.get_megolm_inbound(session_id)
                if inbound_pickle:
                    try:
                        inbound_session = InboundGroupSession.from_pickle(
                            inbound_pickle, self._pickle_key
                        )
                        self._megolm_inbound[session_id] = inbound_session
                    except Exception as e:
                        logger.warning(f"加载入站会话失败，尝试重新创建：{e}")
                        inbound_pickle = None

                # 如果存储中也没有入站会话，从出站会话密钥创建
                if not inbound_pickle:
                    try:
                        inbound_session = InboundGroupSession(session_key)
                        self._megolm_inbound[session_id] = inbound_session
                        self.store.save_megolm_inbound(
                            session_id, inbound_session.pickle(self._pickle_key)
                        )
                        logger.info(
                            f"为出站会话重新创建了入站会话：{session_id[:8]}..."
                        )
                    except Exception as e:
                        logger.warning(f"重新创建入站会话失败：{e}")

            return session_id, session_key.to_base64()
        return None

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

        # 确保入站会话存在，以便能解密自己发送的消息
        session_id = session.session_id
        if session_id not in self._megolm_inbound:
            inbound_pickle = self.store.get_megolm_inbound(session_id)
            if not inbound_pickle:
                try:
                    inbound_session = InboundGroupSession(session.session_key)
                    self._megolm_inbound[session_id] = inbound_session
                    self.store.save_megolm_inbound(
                        session_id, inbound_session.pickle(self._pickle_key)
                    )
                    logger.info(f"为出站会话创建了入站会话：{session_id[:8]}...")
                except Exception as e:
                    logger.warning(f"创建入站会话失败：{e}")

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

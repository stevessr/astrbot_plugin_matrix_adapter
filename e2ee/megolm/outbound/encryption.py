import json

from astrbot.api import logger

from ....constants import MEGOLM_ALGO
from ...olm.types import GroupSession, InboundGroupSession


class OlmMachineMegolmOutboundEncryptionMixin:
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
                    logger.info(
                        f"为出站会话创建了入站会话：{(session_id or '')[:8]}..."
                    )
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
        record_message = getattr(self.store, "record_megolm_outbound_message", None)
        if callable(record_message):
            record_message(room_id, session.session_id)

        return {
            "algorithm": MEGOLM_ALGO,
            "sender_key": self._account.curve25519_key.to_base64()
            if self._account
            else "",
            "session_id": session.session_id,
            "ciphertext": ciphertext.to_base64(),
            "device_id": self.device_id,
        }

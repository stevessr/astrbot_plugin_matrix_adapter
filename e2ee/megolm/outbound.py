import json

from astrbot.api import logger

from ...constants import MEGOLM_ALGO
from ..olm_machine_types import GroupSession, InboundGroupSession


class OlmMachineMegolmOutboundMixin:
    def create_megolm_outbound_session(
        self,
        room_id: str,
        *,
        shared_history: bool = False,
    ) -> tuple[str, str]:
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
        save_outbound_metadata = getattr(
            self.store, "save_megolm_outbound_metadata", None
        )
        if callable(save_outbound_metadata):
            save_outbound_metadata(
                room_id,
                session_id,
                shared_history=shared_history,
            )

        # 同时创建入站会话，以便能解密自己发送的消息
        try:
            inbound_session = InboundGroupSession(session_key)
            self._megolm_inbound[session_id] = inbound_session
            self.store.save_megolm_inbound(
                session_id, inbound_session.pickle(self._pickle_key)
            )
            save_inbound_metadata = getattr(
                self.store, "save_megolm_inbound_metadata", None
            )
            if callable(save_inbound_metadata):
                save_inbound_metadata(
                    session_id,
                    room_id=room_id,
                    sender_key=str(self.curve25519_key),
                    sender_user_id=self.user_id,
                    sender_claimed_keys={"ed25519": str(self.ed25519_key)},
                    shared_history=shared_history,
                )
            logger.debug(f"为自己创建了入站会话：{(session_id or '')[:8]}...")
        except Exception as e:
            logger.warning(f"创建自己的入站会话失败：{e}")

        return session_id, session_key.to_base64()

    def get_megolm_outbound_shared_history(self, room_id: str) -> bool | None:
        """Return the MSC4268 flag for the room's current outbound session."""
        session_info = self.get_megolm_outbound_session_info(room_id)
        get_metadata = getattr(self.store, "get_megolm_outbound_metadata", None)
        metadata = get_metadata(room_id) if callable(get_metadata) else None
        if not session_info or not metadata:
            return None
        if metadata.get("session_id") != session_info[0]:
            return None
        value = metadata.get("shared_history")
        return value if isinstance(value, bool) else None

    def discard_megolm_outbound_session(self, room_id: str) -> bool:
        """Discard an outbound session so the next send rotates it."""
        existed = room_id in self._megolm_outbound or bool(
            self.store.get_megolm_outbound(room_id)
        )
        self._megolm_outbound.pop(room_id, None)
        delete_outbound = getattr(self.store, "delete_megolm_outbound", None)
        if callable(delete_outbound):
            delete_outbound(room_id)
        return existed

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
                            f"为出站会话重新创建了入站会话：{(session_id or '')[:8]}..."
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

    def get_megolm_outbound_room_ids(self) -> list[str]:
        """Get all room IDs that currently have outbound Megolm sessions."""
        room_ids = set(self._megolm_outbound.keys())
        room_ids.update(self.store.get_megolm_outbound_rooms())
        return list(room_ids)

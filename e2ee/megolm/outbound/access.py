from astrbot.api import logger

from ...olm.types import GroupSession, InboundGroupSession


class OlmMachineMegolmOutboundAccessMixin:
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

    def get_megolm_outbound_room_ids(self) -> list[str]:
        """Get all room IDs that currently have outbound Megolm sessions."""
        room_ids = set(self._megolm_outbound.keys())
        room_ids.update(self.store.get_megolm_outbound_rooms())
        return list(room_ids)

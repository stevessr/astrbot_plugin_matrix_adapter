from astrbot.api import logger

from ...olm.types import GroupSession, InboundGroupSession


class OlmMachineMegolmOutboundCreationMixin:
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

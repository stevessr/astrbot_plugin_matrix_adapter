"""Megolm inbound session import orchestration."""

from astrbot.api import logger

from .convert import OlmMachineMegolmInboundImportConvertMixin
from .existing import OlmMachineMegolmInboundImportExistingMixin
from .persist import OlmMachineMegolmInboundImportPersistMixin


class OlmMachineMegolmInboundImportFlowMixin(
    OlmMachineMegolmInboundImportConvertMixin,
    OlmMachineMegolmInboundImportExistingMixin,
    OlmMachineMegolmInboundImportPersistMixin,
):
    """Import Megolm inbound sessions and persist them."""

    def add_megolm_inbound_session(
        self,
        room_id: str,
        session_id: str,
        session_key: str,
        sender_key: str,
        sender_claimed_keys: dict[str, str] | None = None,
        forwarding_curve25519_key_chain: list[str] | None = None,
        shared_history: bool = False,
        sender_user_id: str | None = None,
        withheld: dict[str, str] | None = None,
    ) -> bool:
        """
        添加 Megolm 入站会话 (从 m.room_key 事件或备份恢复)

        Args:
            room_id: 房间 ID
            session_id: 会话 ID
            session_key: 会话密钥 (base64 编码的字符串)
            sender_key: 发送者的 curve25519 密钥
            sender_user_id: Sender Matrix user ID authenticated by the Olm
                plaintext
            sender_claimed_keys: 发送设备声明的签名密钥
            forwarding_curve25519_key_chain: 会话密钥转发链
            shared_history: 该会话是否允许与未来成员共享
            withheld: Forwarded indication for an initially withheld range.

        Returns:
            Whether the session was imported and queued for persistence.
        """
        try:
            session = self._import_megolm_session(session_key, session_id)
            if session is None:
                return False

            candidate_index = self.get_megolm_first_known_index(session)
            existing = self.get_megolm_inbound_session(session_id)

            (
                accepted,
                sender_key,
                sender_user_id,
                sender_claimed_keys,
                forwarding_curve25519_key_chain,
            ) = self._handle_existing_megolm_session(
                session_id,
                existing,
                candidate_index,
                room_id=room_id,
                sender_key=sender_key,
                sender_user_id=sender_user_id,
                sender_claimed_keys=sender_claimed_keys,
                forwarding_curve25519_key_chain=forwarding_curve25519_key_chain,
                shared_history=shared_history,
                withheld=withheld,
            )
            if not accepted:
                return False

            self._megolm_inbound[session_id] = session
            self.store.save_megolm_inbound(
                session_id,
                session.pickle(self._pickle_key),
            )
            logger.debug(f"Added Megolm inbound session: {session_id[:8]}...")
            self._persist_megolm_inbound_metadata(
                session_id,
                room_id=room_id,
                sender_key=sender_key,
                sender_user_id=sender_user_id,
                sender_claimed_keys=sender_claimed_keys,
                forwarding_curve25519_key_chain=forwarding_curve25519_key_chain,
                shared_history=shared_history,
                withheld=withheld,
            )
            return True
        except Exception as e:
            logger.error(f"添加 Megolm 入站会话失败：{e}")
            return False

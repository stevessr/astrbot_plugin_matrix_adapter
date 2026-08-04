"""Megolm inbound session import orchestration."""

from astrbot.api import logger

from ....olm.types import ExportedSessionKey, InboundGroupSession
from ..conversion import _convert_session_key_v2_to_v1


class OlmMachineMegolmInboundImportCoreMixin:
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
            if isinstance(session_key, str):
                # Both full SessionKey (v2) and exported/ratcheted key (v1)
                # payloads are normalized to the import format.
                converted_key = _convert_session_key_v2_to_v1(session_key)
                session = InboundGroupSession.import_session(
                    ExportedSessionKey(converted_key)
                )
            else:
                session = InboundGroupSession(session_key)

            if session.session_id != session_id:
                logger.warning(
                    "Rejected Megolm key whose derived session ID mismatches"
                )
                return False

            candidate_index = self.get_megolm_first_known_index(session)
            existing = self.get_megolm_inbound_session(session_id)
            if existing is not None:
                get_metadata = getattr(
                    self.store,
                    "get_megolm_inbound_metadata",
                    None,
                )
                metadata = get_metadata(session_id) if callable(get_metadata) else None
                if isinstance(metadata, dict):
                    if self._reject_conflicting_megolm_provenance(
                        metadata,
                        room_id,
                        sender_key,
                        sender_user_id,
                        sender_claimed_keys,
                    ):
                        return False
                    (
                        sender_key,
                        sender_user_id,
                        sender_claimed_keys,
                        forwarding_curve25519_key_chain,
                    ) = self._merge_missing_megolm_metadata_fields(
                        metadata,
                        sender_key,
                        sender_user_id,
                        sender_claimed_keys,
                        forwarding_curve25519_key_chain,
                    )

                existing_index = self.get_megolm_first_known_index(existing)
                if candidate_index >= existing_index:
                    # Matrix only permits replacing a stored session with a
                    # trusted copy that starts at a lower message index.
                    self._persist_megolm_inbound_metadata(
                        session_id,
                        room_id=room_id,
                        sender_key=sender_key,
                        sender_user_id=sender_user_id,
                        sender_claimed_keys=sender_claimed_keys,
                        forwarding_curve25519_key_chain=forwarding_curve25519_key_chain,
                        shared_history=shared_history,
                        withheld=withheld,
                        metadata=metadata,
                    )
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

    def _persist_megolm_inbound_metadata(
        self,
        session_id: str,
        *,
        room_id: str,
        sender_key: str | None,
        sender_user_id: str | None,
        sender_claimed_keys: dict[str, str] | None,
        forwarding_curve25519_key_chain: list[str] | None,
        shared_history: bool,
        withheld: dict[str, str] | None,
        metadata: dict | None = None,
    ) -> None:
        """Persist session metadata, merging stored values when available."""
        save_metadata = getattr(self.store, "save_megolm_inbound_metadata", None)
        if not callable(save_metadata):
            return
        if isinstance(metadata, dict):
            save_metadata(
                session_id,
                room_id=metadata.get("room_id", room_id),
                sender_key=metadata.get("sender_key", sender_key),
                sender_user_id=metadata.get("sender_user_id"),
                sender_claimed_keys=metadata.get("sender_claimed_keys"),
                forwarding_curve25519_key_chain=metadata.get(
                    "forwarding_curve25519_key_chain"
                ),
                shared_history=shared_history,
                withheld=withheld,
            )
        else:
            save_metadata(
                session_id,
                room_id=room_id,
                sender_key=sender_key,
                sender_user_id=sender_user_id,
                sender_claimed_keys=sender_claimed_keys,
                forwarding_curve25519_key_chain=forwarding_curve25519_key_chain,
                shared_history=shared_history,
                withheld=withheld,
            )

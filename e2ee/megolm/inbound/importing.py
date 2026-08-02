from astrbot.api import logger

from ...olm.types import ExportedSessionKey, InboundGroupSession
from .conversion import _convert_session_key_v2_to_v1


class OlmMachineMegolmInboundImportMixin:
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
                    existing_room_id = metadata.get("room_id")
                    existing_sender_key = metadata.get("sender_key")
                    existing_sender_user_id = metadata.get("sender_user_id")
                    existing_claimed_keys = metadata.get("sender_claimed_keys")
                    existing_ed25519 = (
                        existing_claimed_keys.get("ed25519")
                        if isinstance(existing_claimed_keys, dict)
                        else None
                    )
                    candidate_ed25519 = (
                        sender_claimed_keys.get("ed25519")
                        if isinstance(sender_claimed_keys, dict)
                        else None
                    )
                    if (
                        isinstance(existing_room_id, str)
                        and existing_room_id
                        and existing_room_id != room_id
                    ) or (
                        isinstance(existing_sender_key, str)
                        and existing_sender_key
                        and isinstance(sender_key, str)
                        and sender_key
                        and existing_sender_key != sender_key
                    ):
                        logger.warning(
                            "Rejected Megolm update with conflicting provenance"
                        )
                        return False
                    if (
                        isinstance(existing_sender_user_id, str)
                        and existing_sender_user_id
                        and isinstance(sender_user_id, str)
                        and sender_user_id
                        and existing_sender_user_id != sender_user_id
                    ):
                        logger.warning(
                            "Rejected Megolm update with a conflicting sender"
                        )
                        return False

                    if not sender_key and isinstance(existing_sender_key, str):
                        sender_key = existing_sender_key
                    if not sender_user_id and isinstance(existing_sender_user_id, str):
                        sender_user_id = existing_sender_user_id
                    if not sender_claimed_keys and isinstance(
                        existing_claimed_keys,
                        dict,
                    ):
                        sender_claimed_keys = existing_claimed_keys
                    if forwarding_curve25519_key_chain is None and isinstance(
                        metadata.get("forwarding_curve25519_key_chain"),
                        list,
                    ):
                        forwarding_curve25519_key_chain = metadata[
                            "forwarding_curve25519_key_chain"
                        ]
                    if (
                        isinstance(existing_ed25519, str)
                        and existing_ed25519
                        and isinstance(candidate_ed25519, str)
                        and candidate_ed25519
                        and existing_ed25519 != candidate_ed25519
                    ):
                        logger.warning(
                            "Rejected Megolm update with a conflicting signing key"
                        )
                        return False

                existing_index = self.get_megolm_first_known_index(existing)
                if candidate_index >= existing_index:
                    # Matrix only permits replacing a stored session with a
                    # trusted copy that starts at a lower message index.
                    save_metadata = getattr(
                        self.store,
                        "save_megolm_inbound_metadata",
                        None,
                    )
                    if callable(save_metadata):
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
                                forwarding_curve25519_key_chain=(
                                    forwarding_curve25519_key_chain
                                ),
                                shared_history=shared_history,
                                withheld=withheld,
                            )
                    return False

            self._megolm_inbound[session_id] = session
            self.store.save_megolm_inbound(
                session_id,
                session.pickle(self._pickle_key),
            )
            logger.debug(f"Added Megolm inbound session: {session_id[:8]}...")
            save_metadata = getattr(self.store, "save_megolm_inbound_metadata", None)
            if callable(save_metadata):
                save_metadata(
                    session_id,
                    room_id=room_id,
                    sender_key=sender_key,
                    sender_user_id=sender_user_id,
                    sender_claimed_keys=sender_claimed_keys,
                    forwarding_curve25519_key_chain=(forwarding_curve25519_key_chain),
                    shared_history=shared_history,
                    withheld=withheld,
                )
            return True
        except Exception as e:
            logger.error(f"添加 Megolm 入站会话失败：{e}")
            return False

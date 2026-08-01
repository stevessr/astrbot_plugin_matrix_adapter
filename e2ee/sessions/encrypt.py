import time

from astrbot.api import logger

from ..constants import (
    DEFAULT_MEGOLM_ROTATION_PERIOD_MS,
    DEFAULT_MEGOLM_ROTATION_PERIOD_MSGS,
)


class E2EEManagerSessionEncryptMixin:

    def _discard_outbound_session(self, room_id: str) -> bool:
        """Discard a room session and its per-session distribution state."""
        if not self._olm:
            return False
        get_session_info = getattr(
            self._olm,
            "get_megolm_outbound_session_info",
            None,
        )
        session_info = get_session_info(room_id) if callable(get_session_info) else None
        session_id = session_info[0] if session_info else None
        discard = getattr(self._olm, "discard_megolm_outbound_session", None)
        discarded = bool(callable(discard) and discard(room_id))
        if discarded and session_id:
            share_cache = getattr(self, "_room_key_share_cache", None)
            if isinstance(share_cache, dict):
                share_cache.pop(session_id, None)
            locks = getattr(self, "_room_key_share_locks", None)
            if isinstance(locks, dict):
                locks.pop(session_id, None)  # always pop, task keeps own reference
        return discarded

    def _outbound_session_is_current(self, room_id: str, session_id: str) -> bool:
        if not self._olm:
            return False
        get_session_info = getattr(
            self._olm,
            "get_megolm_outbound_session_info",
            None,
        )
        if not callable(get_session_info):
            # Lightweight test/custom Olm shims do not expose persistence
            # metadata. The production OlmMachine always does.
            return True
        current = get_session_info(room_id)
        return bool(current and current[0] == session_id)

    async def encrypt_message(
        self, room_id: str, event_type: str, content: dict
    ) -> dict | None:
        """
        加密消息

        Args:
            room_id: 房间 ID
            event_type: 事件类型
            content: 事件内容

        Returns:
            加密后的 m.room.encrypted 内容，或 None
        """
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
            logger.warning("E2EE 未初始化，无法加密")
            return None

        try:
            encryption_configs = getattr(self, "_room_encryption_config", {})
            if not isinstance(encryption_configs, dict) or room_id not in (
                encryption_configs
            ):
                # The state scan also caches custom Megolm rotation limits.
                await self._get_room_members(room_id)
            shared_history = await self._get_room_shared_history(room_id)

            # 检查是否有出站会话
            session_info = self._olm.get_megolm_outbound_session_info(room_id)
            if session_info:
                session_id = session_info[0]
                get_outbound_metadata = getattr(
                    self._store,
                    "get_megolm_outbound_metadata",
                    None,
                )
                metadata = (
                    get_outbound_metadata(room_id)
                    if callable(get_outbound_metadata)
                    else None
                )
                configs = getattr(self, "_room_encryption_config", {})
                encryption_config = (
                    configs.get(room_id) if isinstance(configs, dict) else None
                )
                if not isinstance(encryption_config, dict):
                    encryption_config = {}
                configured_period_ms = encryption_config.get("rotation_period_ms")
                configured_period_msgs = encryption_config.get("rotation_period_msgs")
                rotation_period_ms = (
                    configured_period_ms
                    if type(configured_period_ms) is int and configured_period_ms >= 0
                    else DEFAULT_MEGOLM_ROTATION_PERIOD_MS
                )
                rotation_period_msgs = (
                    configured_period_msgs
                    if type(configured_period_msgs) is int
                    and configured_period_msgs >= 0
                    else DEFAULT_MEGOLM_ROTATION_PERIOD_MSGS
                )
                created_at_ms = (
                    metadata.get("created_at_ms")
                    if isinstance(metadata, dict)
                    and metadata.get("session_id") == session_id
                    else None
                )
                message_count = (
                    metadata.get("message_count")
                    if isinstance(metadata, dict)
                    and metadata.get("session_id") == session_id
                    else None
                )
                rotation_due = (
                    type(created_at_ms) is not int
                    or type(message_count) is not int
                    or int(time.time() * 1000) - created_at_ms >= rotation_period_ms
                    or message_count >= rotation_period_msgs
                )
                if rotation_due and self._discard_outbound_session(room_id):
                    session_info = None

            if session_info:
                metadata_getter = getattr(
                    self._olm,
                    "get_megolm_outbound_shared_history",
                    None,
                )
                session_shared_history = (
                    metadata_getter(room_id) if callable(metadata_getter) else None
                )
                # Legacy sessions have no MSC4268 metadata. Rotate them rather
                # than incorrectly claiming that their history is shareable.
                if session_shared_history is None or (
                    session_shared_history != shared_history
                ):
                    if self._discard_outbound_session(room_id):
                        session_info = None
            if not session_info:
                # 创建新会话并分发密钥
                await self._create_and_share_session(
                    room_id,
                    shared_history=shared_history,
                )
            else:
                # 会话已存在，确保密钥已分发给所有成员
                session_id, session_key = session_info
                members = await self._get_room_members(room_id)
                if members:
                    await self.ensure_room_keys_sent(
                        room_id,
                        members,
                        session_id,
                        session_key,
                        reason="send_message",
                        shared_history=shared_history,
                    )

            # 加密消息
            return self._olm.encrypt_megolm(room_id, event_type, content)

        except Exception as e:
            logger.error(f"加密消息失败：{e}")
            return None

    async def _create_and_share_session(
        self,
        room_id: str,
        *,
        shared_history: bool = False,
    ):
        """创建 Megolm 出站会话并分发密钥"""
        if not self._olm:
            return

        # 创建会话
        session_id, session_key = self._olm.create_megolm_outbound_session(
            room_id,
            shared_history=shared_history,
        )
        logger.info(f"为房间 {room_id} 创建了 Megolm 会话")

        # 获取房间成员
        try:
            members = await self._get_room_members(room_id, force_refresh=True)
            if members:
                await self.ensure_room_keys_sent(
                    room_id,
                    members,
                    session_id,
                    session_key,
                    reason="new_session",
                    shared_history=shared_history,
                )
        except Exception as e:
            logger.error(f"分发密钥失败：{e}")


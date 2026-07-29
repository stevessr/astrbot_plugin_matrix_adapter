import asyncio
import secrets
import time

from astrbot.api import logger

from ..constants import (
    M_ROOM_ENCRYPTED,
    M_ROOM_ENCRYPTION,
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_KEY,
    M_ROOM_MEMBER,
    MEGOLM_ALGO,
    MEMBERSHIP_INVITE,
    MEMBERSHIP_JOIN,
    PREFIX_CURVE25519,
    PREFIX_ED25519,
    SIGNED_CURVE25519,
)
from .constants import (
    DEFAULT_HISTORY_VISIBILITY,
    DEFAULT_MEGOLM_ROTATION_PERIOD_MS,
    DEFAULT_MEGOLM_ROTATION_PERIOD_MSGS,
    DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC,
    HISTORY_VISIBILITY_INVITED,
    HISTORY_VISIBILITY_JOINED,
    INVITE_KEY_SHARE_VISIBILITIES,
    SHAREABLE_HISTORY_VISIBILITIES,
    VALID_HISTORY_VISIBILITIES,
)


class E2EEManagerSessionsMixin:
    @staticmethod
    def _device_cache_key(user_id: str, device_id: str, curve25519_key: str) -> str:
        return f"{user_id}|{device_id}|{curve25519_key}"

    def invalidate_room_members_cache(self, room_id: str) -> None:
        """Invalidate member cache for a room to force fresh state query next time."""
        cache = getattr(self, "_room_members_cache", None)
        if isinstance(cache, dict):
            cache.pop(room_id, None)

    def set_room_encryption_config(self, room_id: str, content: object) -> None:
        """Cache the current m.room.encryption rotation policy for a room."""
        configs = getattr(self, "_room_encryption_config", None)
        if not isinstance(configs, dict):
            configs = {}
            self._room_encryption_config = configs
        if isinstance(room_id, str) and room_id and isinstance(content, dict):
            configs[room_id] = dict(content)

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

    @staticmethod
    def _normalize_history_visibility(value: object) -> str:
        if isinstance(value, str) and value in VALID_HISTORY_VISIBILITIES:
            return value
        # Matrix defines a missing/invalid history visibility as ``shared``.
        return DEFAULT_HISTORY_VISIBILITY

    @classmethod
    def _history_visibility_is_shareable(cls, value: object) -> bool:
        return (
            cls._normalize_history_visibility(value) in SHAREABLE_HISTORY_VISIBILITIES
        )

    async def _get_room_history_visibility(
        self,
        room_id: str,
        *,
        force_refresh: bool = False,
    ) -> str:
        """Resolve and cache the room's normalized history visibility.

        A missing state event has the Matrix default of ``shared``.  A
        transient request failure is handled conservatively as ``joined`` and
        is not cached, so no key is exposed to an invitee based on stale data.
        """
        cache = getattr(self, "_room_history_visibility", None)
        if not isinstance(cache, dict):
            cache = {}
            self._room_history_visibility = cache
        if not force_refresh and room_id in cache:
            return self._normalize_history_visibility(cache[room_id])

        try:
            content = await self.client.get_room_state_event(
                room_id,
                M_ROOM_HISTORY_VISIBILITY,
                "",
            )
        except Exception as e:
            if getattr(e, "status", None) == 404:
                cache[room_id] = DEFAULT_HISTORY_VISIBILITY
                return DEFAULT_HISTORY_VISIBILITY
            logger.warning(
                "Failed to read room history visibility; defaulting "
                f"conservatively to joined: room={room_id} error={e}"
            )
            return HISTORY_VISIBILITY_JOINED

        visibility = (
            content.get("history_visibility") if isinstance(content, dict) else None
        )
        normalized = self._normalize_history_visibility(visibility)
        cache[room_id] = normalized
        return normalized

    async def _get_room_shared_history(
        self,
        room_id: str,
        *,
        force_refresh: bool = False,
    ) -> bool:
        """Resolve whether new Megolm sessions may be shared with invitees.

        Matrix treats an absent/unknown ``m.room.history_visibility`` event as
        ``shared``. Transient request failures are handled conservatively and
        are not cached, so a later send can retry.
        """
        visibility = await self._get_room_history_visibility(
            room_id,
            force_refresh=force_refresh,
        )
        return self._history_visibility_is_shareable(visibility)

    async def on_history_visibility_changed(
        self,
        room_id: str,
        previous: object,
        current: object,
    ) -> None:
        """Rotate Megolm when history visibility changes its key audience."""
        normalized_previous = self._normalize_history_visibility(previous)
        normalized_current = self._normalize_history_visibility(current)
        cache = getattr(self, "_room_history_visibility", None)
        if isinstance(cache, dict):
            cache[room_id] = normalized_current
        self.invalidate_room_members_cache(room_id)

        previous_policy = (
            self._history_visibility_is_shareable(normalized_previous),
            normalized_previous in INVITE_KEY_SHARE_VISIBILITIES,
        )
        current_policy = (
            self._history_visibility_is_shareable(normalized_current),
            normalized_current in INVITE_KEY_SHARE_VISIBILITIES,
        )
        if previous_policy == current_policy:
            return

        if self._discard_outbound_session(room_id):
            logger.info(
                "房间历史可见性改变，已轮换 Megolm 出站会话："
                f"room={room_id} previous={previous} current={normalized_current}"
            )

    async def on_room_member_joined(self, room_id: str, user_id: str) -> None:
        """Share allowed history, or rotate before encrypting for a new member."""
        if user_id == self.user_id:
            return
        self.invalidate_room_members_cache(room_id)

        metadata_getter = getattr(
            self._olm,
            "get_megolm_outbound_shared_history",
            None,
        )
        shared_history = metadata_getter(room_id) if callable(metadata_getter) else None
        if shared_history is not True:
            # A non-shareable (or legacy/unknown) session must not be handed to
            # a user who joined after it was created. The next send creates and
            # distributes a fresh session to the current membership instead.
            self._discard_outbound_session(room_id)
            return

        await self._share_existing_room_key(
            room_id=room_id,
            target_users=[user_id],
            reason="member_join",
            force_members_refresh=True,
        )

    async def on_room_member_invited(self, room_id: str, user_id: str) -> None:
        """Apply history-visibility rules when an encrypted-room invite lands."""
        if user_id == self.user_id:
            return
        self.invalidate_room_members_cache(room_id)
        visibility = await self._get_room_history_visibility(
            room_id,
            force_refresh=True,
        )
        if visibility == HISTORY_VISIBILITY_JOINED:
            return
        if visibility == HISTORY_VISIBILITY_INVITED:
            # An invitee may read messages sent after the invite, but must not
            # receive the session that encrypted messages from before it.
            self._discard_outbound_session(room_id)
            return
        if visibility not in INVITE_KEY_SHARE_VISIBILITIES:
            return

        metadata_getter = getattr(
            self._olm,
            "get_megolm_outbound_shared_history",
            None,
        )
        if callable(metadata_getter) and metadata_getter(room_id) is True:
            await self._share_existing_room_key(
                room_id=room_id,
                target_users=[user_id],
                reason="member_invite",
                force_members_refresh=True,
            )

    async def on_room_member_left(self, room_id: str, user_id: str) -> None:
        """Rotate so a departed or banned member cannot decrypt future events."""
        self.invalidate_room_members_cache(room_id)
        if user_id == self.user_id:
            return
        self._discard_outbound_session(room_id)

    async def on_device_list_changed(self, changed_users: list[str]) -> None:
        """Re-check key sharing when users publish device-list changes.

        This event-driven path remains active in lazy mode so newly announced
        devices can receive an existing outbound room key without a periodic scan.

        Args:
            changed_users: Matrix users whose device lists changed.
        """
        if not self._olm or not self._initialized:
            return

        changed_set = {
            user_id for user_id in changed_users if user_id and isinstance(user_id, str)
        }
        if not changed_set:
            return

        room_ids = self._olm.get_megolm_outbound_room_ids()
        if not room_ids:
            return

        try:
            response = await self.client.query_keys(
                {user_id: [] for user_id in changed_set}
            )
        except Exception as e:
            logger.warning(f"Failed to refresh changed device list: {e}")
            return
        response_devices = response.get("device_keys", {})
        if not isinstance(response_devices, dict):
            return

        # user -> whether a previously known device disappeared or changed
        destructive_changes: dict[str, bool] = {}
        for user_id in changed_set:
            if user_id not in response_devices:
                # A partial/federation failure must not be interpreted as all
                # devices being deleted.
                continue
            raw_current = response_devices.get(user_id)
            if not isinstance(raw_current, dict):
                continue
            current = {
                device_id: device_info
                for device_id, device_info in raw_current.items()
                if isinstance(device_id, str)
                and self._olm.verify_device_keys(user_id, device_id, device_info)
            }
            previous = {}
            if self._store:
                all_keys = self._store.get_all_device_keys()
                previous = (
                    all_keys.get(user_id) or {} if isinstance(all_keys, dict) else {}
                )

            def identity_map(devices: object) -> dict[str, tuple[str, str]]:
                if not isinstance(devices, dict):
                    return {}
                identities: dict[str, tuple[str, str]] = {}
                for device_id, device_info in devices.items():
                    if not isinstance(device_info, dict):
                        continue
                    keys = device_info.get("keys") or {}
                    curve = keys.get(f"{PREFIX_CURVE25519}{device_id}")
                    ed = keys.get(f"{PREFIX_ED25519}{device_id}")
                    if isinstance(curve, str) and isinstance(ed, str):
                        identities[str(device_id)] = (curve, ed)
                return identities

            old_identities = identity_map(previous)
            new_identities = identity_map(current)
            destructive_changes[user_id] = any(
                new_identities.get(device_id) != identity
                for device_id, identity in old_identities.items()
            )
            if self._store:
                replace = getattr(self._store, "replace_user_device_keys", None)
                if callable(replace):
                    replace(user_id, current)
                else:
                    for device_id, device_info in current.items():
                        self._store.save_device_keys(user_id, device_id, device_info)

        if not destructive_changes:
            return

        affected_rooms = 0
        affected_users = 0
        for room_id in room_ids:
            members = await self._get_room_members(room_id)
            if not members:
                continue
            target_users = [user_id for user_id in members if user_id in changed_set]
            if not target_users:
                continue
            if any(destructive_changes.get(user_id) for user_id in target_users):
                # A removed/re-keyed device already has the current Megolm key;
                # rotate before any future message rather than only updating
                # the share cache for newly added devices.
                self._discard_outbound_session(room_id)
                affected_rooms += 1
                affected_users += len(target_users)
                continue
            await self._share_existing_room_key(
                room_id=room_id,
                target_users=target_users,
                reason="device_list_changed",
            )
            affected_rooms += 1
            affected_users += len(target_users)

        if affected_rooms:
            logger.info(
                f"设备列表变更后已主动检查密钥分发：rooms={affected_rooms} users={affected_users}"
            )

    async def on_device_list_left(self, left_users: list[str]) -> None:
        """Forget users for whom /sync says no encrypted rooms are shared."""
        left = {user_id for user_id in left_users if isinstance(user_id, str)}
        if not left:
            return
        if self._store:
            delete = getattr(self._store, "delete_user_device_keys", None)
            if callable(delete):
                for user_id in left:
                    delete(user_id)
        share_cache = getattr(self, "_room_key_share_cache", {})
        for shared_devices in share_cache.values():
            shared_devices.difference_update(
                cache_key
                for cache_key in tuple(shared_devices)
                if cache_key.split("|", 1)[0] in left
            )

    async def _share_existing_room_key(
        self,
        room_id: str,
        target_users: list[str] | None = None,
        reason: str = "proactive",
        force_members_refresh: bool = False,
    ) -> None:
        """Share an existing outbound Megolm session key to selected users."""
        if not self._olm or not self._initialized:
            return

        session_info = self._olm.get_megolm_outbound_session_info(room_id)
        if not session_info:
            return
        session_id, session_key = session_info

        members = await self._get_room_members(
            room_id, force_refresh=force_members_refresh
        )

        if not members:
            return

        await self.ensure_room_keys_sent(
            room_id=room_id,
            members=members,
            session_id=session_id,
            session_key=session_key,
            target_users=target_users,
            reason=reason,
        )

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
        if not self._olm or not self._initialized:
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

    async def _get_room_members(
        self, room_id: str, force_refresh: bool = False
    ) -> list[str]:
        """获取房间成员列表"""
        cache = getattr(self, "_room_members_cache", None)
        cache_ttl = float(
            getattr(
                self,
                "_room_members_cache_ttl_sec",
                DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC,
            )
        )
        if (
            not force_refresh
            and isinstance(cache, dict)
            and room_id in cache
            and isinstance(cache[room_id], tuple)
            and len(cache[room_id]) == 2
        ):
            members, ts = cache[room_id]
            if (time.monotonic() - float(ts)) <= cache_ttl:
                return list(members)

        try:
            state = await self.client.get_room_state(room_id)
            visibility = None
            for event in state:
                if (
                    event.get("type") == M_ROOM_ENCRYPTION
                    and event.get("state_key", "") == ""
                ):
                    self.set_room_encryption_config(
                        room_id,
                        event.get("content") or {},
                    )
                if (
                    event.get("type") == M_ROOM_HISTORY_VISIBILITY
                    and event.get("state_key", "") == ""
                ):
                    visibility = (event.get("content") or {}).get("history_visibility")
            if visibility is None:
                visibility = await self._get_room_history_visibility(room_id)
            else:
                visibility = self._normalize_history_visibility(visibility)
                history_cache = getattr(self, "_room_history_visibility", None)
                if not isinstance(history_cache, dict):
                    history_cache = {}
                    self._room_history_visibility = history_cache
                history_cache[room_id] = visibility
            include_invited = visibility in INVITE_KEY_SHARE_VISIBILITIES
            members = []
            for event in state:
                if event.get("type") == M_ROOM_MEMBER:
                    membership = event.get("content", {}).get("membership")
                    if membership == MEMBERSHIP_JOIN or (
                        include_invited and membership == MEMBERSHIP_INVITE
                    ):
                        state_key = event.get("state_key")
                        if state_key:
                            members.append(state_key)
            unique_members = list(dict.fromkeys(members))
            if isinstance(cache, dict):
                cache[room_id] = (unique_members, time.monotonic())
            return unique_members
        except Exception as e:
            logger.warning(f"获取房间成员失败：{e}")
            return []

    async def ensure_room_keys_sent(
        self,
        room_id: str,
        members: list[str],
        session_id: str | None = None,
        session_key: str | None = None,
        target_users: list[str] | None = None,
        reason: str = "sync",
        shared_history: bool | None = None,
    ) -> int:
        """
        确保房间密钥已发送给所有成员的设备

        Args:
            room_id: 房间 ID
            members: 成员用户 ID 列表
            session_id: 可选，指定会话 ID
            session_key: 可选，指定会话密钥
            target_users: 可选，只分发给指定用户（其余成员跳过）
            reason: 日志用途，标记分发触发原因
            shared_history: MSC4268 会话是否允许与未来成员共享

        Returns:
            Number of devices that received the room key successfully.
        """
        if not self._olm or not members:
            return 0

        normalized_members = list(
            dict.fromkeys(user_id for user_id in members if user_id)
        )
        if not normalized_members:
            return 0

        if target_users is not None:
            target_set = {
                user_id
                for user_id in target_users
                if user_id and isinstance(user_id, str)
            }
            if not target_set:
                return 0
            normalized_members = [
                user_id for user_id in normalized_members if user_id in target_set
            ]
            if not normalized_members:
                return 0

        # 如果没有提供会话信息，获取当前出站会话
        if not session_id or not session_key:
            session_info = self._olm.get_megolm_outbound_session_info(room_id)
            if not session_info:
                logger.warning(f"房间 {room_id} 没有出站会话")
                return 0
            session_id, session_key = session_info

        locks = getattr(self, "_room_key_share_locks", None)
        if not isinstance(locks, dict):
            locks = {}
            self._room_key_share_locks = locks
        lock = locks.setdefault(session_id, asyncio.Lock())
        async with lock:
            return await self._ensure_room_keys_sent_locked(
                room_id=room_id,
                members=normalized_members,
                session_id=session_id,
                session_key=session_key,
                reason=reason,
                shared_history=shared_history,
            )

    async def _ensure_room_keys_sent_locked(
        self,
        *,
        room_id: str,
        members: list[str],
        session_id: str,
        session_key: str,
        reason: str,
        shared_history: bool | None,
    ) -> int:
        """Distribute one session while its per-session lock is held."""
        if not self._outbound_session_is_current(room_id, session_id):
            logger.debug(
                f"Skip stale room-key distribution: room={room_id} "
                f"session={session_id[:8]}..."
            )
            return 0

        shared_devices = self._room_key_share_cache.setdefault(session_id, set())
        if shared_history is None:
            metadata_getter = getattr(
                self._olm,
                "get_megolm_outbound_shared_history",
                None,
            )
            shared_history = (
                metadata_getter(room_id) if callable(metadata_getter) else None
            )
        # Unknown/legacy metadata must not be promoted to shareable.
        shared_history = shared_history is True

        try:
            response = await self.client.query_keys(
                {user_id: [] for user_id in members}
            )
            device_keys = response.get("device_keys", {})
            if not isinstance(device_keys, dict):
                return 0

            member_set = set(members)
            devices_to_send: list[tuple[str, str, str, str]] = []
            for user_id, user_devices in device_keys.items():
                if user_id not in member_set or not isinstance(user_devices, dict):
                    continue
                for device_id, device_info in user_devices.items():
                    if user_id == self.user_id and device_id == self.device_id:
                        continue
                    if not self._olm.verify_device_keys(
                        user_id,
                        device_id,
                        device_info,
                    ):
                        logger.warning(
                            "Ignoring device with invalid Matrix self-signature: "
                            f"{user_id}/{device_id}"
                        )
                        continue

                    keys = device_info.get("keys", {})
                    curve_key = keys.get(f"{PREFIX_CURVE25519}{device_id}")
                    ed_key = keys.get(f"{PREFIX_ED25519}{device_id}")
                    if not isinstance(curve_key, str) or not isinstance(ed_key, str):
                        continue
                    if self._store:
                        self._store.save_device_keys(user_id, device_id, device_info)

                    cache_key = self._device_cache_key(user_id, device_id, curve_key)
                    if cache_key not in shared_devices:
                        devices_to_send.append((user_id, device_id, curve_key, ed_key))

            if not devices_to_send:
                logger.debug(
                    f"No devices eligible for room-key sharing: "
                    f"room={room_id} reason={reason} "
                    f"members={len(members)}"
                )
                return 0

            one_time_claim: dict[str, dict[str, str]] = {}
            for user_id, device_id, curve_key, _ in devices_to_send:
                if not self._olm.get_olm_session(curve_key):
                    one_time_claim.setdefault(user_id, {})[device_id] = (
                        SIGNED_CURVE25519
                    )

            one_time_keys = {}
            if one_time_claim:
                claimed = await self.client.claim_keys(one_time_claim)
                one_time_keys = claimed.get("one_time_keys", {})
                if not isinstance(one_time_keys, dict):
                    one_time_keys = {}

            sent_count = 0
            for user_id, device_id, curve_key, ed_key in devices_to_send:
                try:
                    # Membership/device callbacks may rotate this session while
                    # the network requests above are in flight.
                    if not self._outbound_session_is_current(room_id, session_id):
                        logger.debug("Room-key distribution stopped after rotation")
                        break

                    session = self._olm.get_olm_session(curve_key)
                    if not session:
                        device_otks = (one_time_keys.get(user_id) or {}).get(
                            device_id
                        ) or {}
                        selected = self._olm.select_verified_one_time_key(
                            user_id,
                            device_id,
                            ed_key,
                            device_otks,
                        )
                        if not selected:
                            logger.warning(
                                "No valid signed one-time key for "
                                f"{user_id}/{device_id}"
                            )
                            send_no_olm = getattr(
                                self,
                                "_send_no_olm_withheld",
                                None,
                            )
                            if callable(send_no_olm):
                                await send_no_olm(user_id, device_id)
                            continue
                        _, one_time_key = selected
                        session = self._olm.create_outbound_session(
                            curve_key,
                            one_time_key,
                        )

                    room_key_content = {
                        "algorithm": MEGOLM_ALGO,
                        "room_id": room_id,
                        "session_id": session_id,
                        "session_key": session_key,
                        "shared_history": shared_history,
                    }
                    encrypted_content = self._olm.encrypt_olm(
                        curve_key,
                        room_key_content,
                        session=session,
                        recipient_user_id=user_id,
                        recipient_ed25519_key=ed_key,
                        event_type=M_ROOM_KEY,
                    )
                    await self.client.send_to_device(
                        M_ROOM_ENCRYPTED,
                        {user_id: {device_id: encrypted_content}},
                        secrets.token_hex(16),
                    )
                    mark_succeeded = getattr(
                        self,
                        "_mark_olm_send_succeeded",
                        None,
                    )
                    if callable(mark_succeeded):
                        mark_succeeded(user_id, device_id)
                    shared_devices.add(
                        self._device_cache_key(user_id, device_id, curve_key)
                    )
                    sent_count += 1
                except Exception as e:
                    logger.warning(f"向 {user_id}/{device_id} 发送密钥失败：{e}")

            logger.info(
                f"已向 {sent_count}/{len(devices_to_send)} 个设备分发房间 {room_id} 的密钥 "
                f"(reason={reason})"
            )
            return sent_count
        except Exception as e:
            logger.error(f"密钥分发失败：{e}")
            return 0

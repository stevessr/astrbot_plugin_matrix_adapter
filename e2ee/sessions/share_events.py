import time

from astrbot.api import logger

from ...constants import (
    M_ROOM_ENCRYPTION,
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_MEMBER,
    MEMBERSHIP_INVITE,
    MEMBERSHIP_JOIN,
    PREFIX_CURVE25519,
    PREFIX_ED25519,
)
from ..constants import (
    DEFAULT_HISTORY_VISIBILITY,
    DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC,
    HISTORY_VISIBILITY_INVITED,
    HISTORY_VISIBILITY_JOINED,
    INVITE_KEY_SHARE_VISIBILITIES,
    SHAREABLE_HISTORY_VISIBILITIES,
    VALID_HISTORY_VISIBILITIES,
)


class E2EEManagerSessionShareEventsMixin:

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
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
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


import time

from astrbot.api import logger

from ..constants import (
    M_ROOM_ENCRYPTED,
    M_ROOM_KEY,
    M_ROOM_MEMBER,
    MEGOLM_ALGO,
    MEMBERSHIP_INVITE,
    MEMBERSHIP_JOIN,
    PREFIX_CURVE25519,
    PREFIX_ED25519,
    SIGNED_CURVE25519,
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

    async def on_room_member_joined(self, room_id: str, user_id: str) -> None:
        """Proactively share existing room key to a newly joined member."""
        if user_id == self.user_id:
            return
        self.invalidate_room_members_cache(room_id)
        await self._share_existing_room_key(
            room_id=room_id,
            target_users=[user_id],
            reason="member_join",
            force_members_refresh=True,
        )

    async def on_device_list_changed(self, changed_users: list[str]) -> None:
        """Proactively re-check key sharing when users publish device list changes."""
        if not self._olm or not self._initialized:
            return

        changed_set = {
            user_id
            for user_id in changed_users
            if user_id and isinstance(user_id, str) and user_id != self.user_id
        }
        if not changed_set:
            return

        room_ids = self._olm.get_megolm_outbound_room_ids()
        if not room_ids:
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
        if target_users:
            member_set = set(members)
            for user_id in target_users:
                if user_id and user_id != self.user_id and user_id not in member_set:
                    members.append(user_id)
                    member_set.add(user_id)

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
            # 检查是否有出站会话
            session_info = self._olm.get_megolm_outbound_session_info(room_id)
            if not session_info:
                # 创建新会话并分发密钥
                await self._create_and_share_session(room_id)
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
                    )

            # 加密消息
            return self._olm.encrypt_megolm(room_id, event_type, content)

        except Exception as e:
            logger.error(f"加密消息失败：{e}")
            return None

    async def _create_and_share_session(self, room_id: str):
        """创建 Megolm 出站会话并分发密钥"""
        if not self._olm:
            return

        # 创建会话
        session_id, session_key = self._olm.create_megolm_outbound_session(room_id)
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
                )
        except Exception as e:
            logger.error(f"分发密钥失败：{e}")

    async def _get_room_members(
        self, room_id: str, force_refresh: bool = False
    ) -> list[str]:
        """获取房间成员列表"""
        cache = getattr(self, "_room_members_cache", None)
        cache_ttl = float(getattr(self, "_room_members_cache_ttl_sec", 30.0))
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
            members = []
            for event in state:
                if event.get("type") == M_ROOM_MEMBER:
                    membership = event.get("content", {}).get("membership")
                    if membership in [MEMBERSHIP_JOIN, MEMBERSHIP_INVITE]:
                        state_key = event.get("state_key")
                        if state_key and state_key != self.user_id:
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
    ) -> None:
        """
        确保房间密钥已发送给所有成员的设备

        Args:
            room_id: 房间 ID
            members: 成员用户 ID 列表
            session_id: 可选，指定会话 ID
            session_key: 可选，指定会话密钥
            target_users: 可选，只分发给指定用户（其余成员跳过）
            reason: 日志用途，标记分发触发原因
        """
        if not self._olm or not members:
            return

        normalized_members = list(
            dict.fromkeys(
                user_id for user_id in members if user_id and user_id != self.user_id
            )
        )
        if not normalized_members:
            return

        if target_users is not None:
            target_set = {
                user_id
                for user_id in target_users
                if user_id and isinstance(user_id, str) and user_id != self.user_id
            }
            if not target_set:
                return
            normalized_members = [
                user_id for user_id in normalized_members if user_id in target_set
            ]
            if not normalized_members:
                return

        # 如果没有提供会话信息，获取当前出站会话
        if not session_id or not session_key:
            session_info = self._olm.get_megolm_outbound_session_info(room_id)
            if not session_info:
                logger.warning(f"房间 {room_id} 没有出站会话")
                return
            session_id, session_key = session_info

        shared_devices = self._room_key_share_cache.setdefault(session_id, set())

        try:
            # 查询目标成员的设备密钥
            device_keys_query = {user_id: [] for user_id in normalized_members}
            response = await self.client.query_keys(device_keys_query)

            device_keys = response.get("device_keys", {})
            devices_to_send: list[
                tuple[str, str, str, str]
            ] = []  # (user_id, device_id, curve25519_key, ed25519_key)

            for user_id, user_devices in device_keys.items():
                for device_id, device_info in user_devices.items():
                    keys = device_info.get("keys", {})
                    curve_key = keys.get(f"{PREFIX_CURVE25519}{device_id}")
                    ed_key = keys.get(f"{PREFIX_ED25519}{device_id}")
                    if not curve_key:
                        continue

                    if self._store:
                        self._store.save_device_keys(user_id, device_id, device_info)

                    cache_key = self._device_cache_key(user_id, device_id, curve_key)
                    if cache_key in shared_devices:
                        continue

                    devices_to_send.append(
                        (user_id, device_id, curve_key, ed_key or "unknown")
                    )

            if not devices_to_send:
                logger.debug(
                    f"没有需要发送密钥的设备：room={room_id} reason={reason} members={len(normalized_members)}"
                )
                return

            # 声明一次性密钥（只为没有现有会话的设备）
            one_time_claim = {}
            for user_id, device_id, curve_key, _ in devices_to_send:
                if not self._olm.get_olm_session(curve_key):
                    if user_id not in one_time_claim:
                        one_time_claim[user_id] = {}
                    one_time_claim[user_id][device_id] = SIGNED_CURVE25519

            one_time_keys = {}
            if one_time_claim:
                claimed = await self.client.claim_keys(one_time_claim)
                one_time_keys = claimed.get("one_time_keys", {})

            # 为每个设备发送 m.room_key
            import secrets

            sent_count = 0
            for user_id, device_id, curve_key, ed_key in devices_to_send:
                try:
                    # 检查是否已有 Olm 会话
                    existing_session = self._olm.get_olm_session(curve_key)

                    if existing_session:
                        # 使用现有会话
                        session = existing_session
                        logger.debug(
                            f"复用现有 Olm 会话向 {user_id}/{device_id} 发送密钥"
                        )
                    else:
                        # 需要创建新会话，获取一次性密钥
                        user_otks = one_time_keys.get(user_id, {})
                        device_otks = user_otks.get(device_id, {})

                        if not device_otks:
                            logger.debug(
                                f"设备 {user_id}/{device_id} 没有可用的一次性密钥"
                            )
                            continue

                        # 取一个可用的一次性密钥
                        otk_id, otk_data = next(iter(device_otks.items()), (None, None))
                        if not otk_id:
                            logger.debug(
                                f"设备 {user_id}/{device_id} 未返回可用的一次性密钥条目"
                            )
                            continue
                        one_time_key = (
                            otk_data.get("key")
                            if isinstance(otk_data, dict)
                            else otk_data
                        )
                        if not one_time_key:
                            logger.debug(
                                f"设备 {user_id}/{device_id} 的一次性密钥内容为空"
                            )
                            continue

                        # 创建 Olm 会话
                        session = self._olm.create_outbound_session(
                            curve_key, one_time_key
                        )
                        logger.debug(f"为 {user_id}/{device_id} 创建新 Olm 会话")

                    # 构造 m.room_key 内容
                    room_key_content = {
                        "type": M_ROOM_KEY,
                        "algorithm": MEGOLM_ALGO,
                        "room_id": room_id,
                        "session_id": session_id,
                        "session_key": session_key,
                    }

                    # 使用 Olm 加密并包装
                    encrypted_content = self._olm.encrypt_olm(
                        curve_key,
                        room_key_content,
                        session=session,
                        recipient_user_id=user_id,
                        recipient_ed25519_key=ed_key,
                    )

                    txn_id = secrets.token_hex(16)
                    await self.client.send_to_device(
                        M_ROOM_ENCRYPTED,
                        {user_id: {device_id: encrypted_content}},
                        txn_id,
                    )

                    shared_devices.add(
                        self._device_cache_key(user_id, device_id, curve_key)
                    )
                    sent_count += 1
                    logger.debug(f"已向 {user_id}/{device_id} 发送房间密钥")

                except Exception as e:
                    logger.warning(f"向 {user_id}/{device_id} 发送密钥失败：{e}")

            logger.info(
                f"已向 {sent_count}/{len(devices_to_send)} 个设备分发房间 {room_id} 的密钥 "
                f"(reason={reason})"
            )

        except Exception as e:
            logger.error(f"密钥分发失败：{e}")

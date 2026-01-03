from astrbot.api import logger

from ..constants import (
    M_ROOM_ENCRYPTED,
    M_ROOM_KEY,
    M_ROOM_MEMBER,
    MEGOLM_ALGO,
    MEMBERSHIP_INVITE,
    MEMBERSHIP_JOIN,
    PREFIX_CURVE25519,
    SIGNED_CURVE25519,
)


class E2EEManagerSessionsMixin:
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
            if not self._store or not self._store.get_megolm_outbound(room_id):
                # 创建新会话并分发密钥
                await self._create_and_share_session(room_id)

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
            members = await self._get_room_members(room_id)
            if members:
                await self.ensure_room_keys_sent(
                    room_id, members, session_id, session_key
                )
        except Exception as e:
            logger.error(f"分发密钥失败：{e}")

    async def _get_room_members(self, room_id: str) -> list[str]:
        """获取房间成员列表"""
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
            return members
        except Exception as e:
            logger.warning(f"获取房间成员失败：{e}")
            return []

    async def ensure_room_keys_sent(
        self,
        room_id: str,
        members: list[str],
        session_id: str | None = None,
        session_key: str | None = None,
    ):
        """
        确保房间密钥已发送给所有成员的设备

        Args:
            room_id: 房间 ID
            members: 成员用户 ID 列表
            session_id: 可选，指定会话 ID
            session_key: 可选，指定会话密钥
        """
        if not self._olm or not members:
            return

        # 如果没有提供会话信息，获取当前出站会话
        if not session_id or not session_key:
            outbound = self._store.get_megolm_outbound(room_id) if self._store else None
            if not outbound:
                logger.warning(f"房间 {room_id} 没有出站会话")
                return
            # 需要从会话中获取信息
            session_id, session_key = self._olm.create_megolm_outbound_session(room_id)

        try:
            # 查询所有成员的设备密钥
            device_keys_query = {user_id: [] for user_id in members}
            response = await self.client.query_keys(device_keys_query)

            device_keys = response.get("device_keys", {})
            devices_to_send: list[
                tuple[str, str, str]
            ] = []  # (user_id, device_id, curve25519_key)

            for user_id, user_devices in device_keys.items():
                for device_id, device_info in user_devices.items():
                    keys = device_info.get("keys", {})
                    curve_key = keys.get(f"{PREFIX_CURVE25519}{device_id}")
                    if curve_key:
                        devices_to_send.append((user_id, device_id, curve_key))

            if not devices_to_send:
                logger.debug("没有设备需要发送密钥")
                return

            # 声明一次性密钥
            one_time_claim = {}
            for user_id, device_id, _ in devices_to_send:
                if user_id not in one_time_claim:
                    one_time_claim[user_id] = {}
                one_time_claim[user_id][device_id] = SIGNED_CURVE25519

            claimed = await self.client.claim_keys(one_time_claim)
            one_time_keys = claimed.get("one_time_keys", {})

            # 为每个设备发送 m.room_key
            import secrets

            for user_id, device_id, curve_key in devices_to_send:
                try:
                    # 获取声明的一次性密钥
                    user_otks = one_time_keys.get(user_id, {})
                    device_otks = user_otks.get(device_id, {})

                    if not device_otks:
                        logger.debug(f"设备 {user_id}/{device_id} 没有可用的一次性密钥")
                        continue

                    # 取第一个一次性密钥
                    otk_id = list(device_otks.keys())[0]
                    otk_data = device_otks[otk_id]
                    one_time_key = (
                        otk_data.get("key") if isinstance(otk_data, dict) else otk_data
                    )

                    # 创建 Olm 会话
                    session = self._olm.create_outbound_session(curve_key, one_time_key)

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
                    )

                    txn_id = secrets.token_hex(16)
                    await self.client.send_to_device(
                        M_ROOM_ENCRYPTED,
                        {user_id: {device_id: encrypted_content}},
                        txn_id,
                    )

                    logger.debug(f"已向 {user_id}/{device_id} 发送房间密钥")

                except Exception as e:
                    logger.warning(f"向 {user_id}/{device_id} 发送密钥失败：{e}")

            logger.info(f"已向 {len(devices_to_send)} 个设备分发房间 {room_id} 的密钥")

        except Exception as e:
            logger.error(f"密钥分发失败：{e}")

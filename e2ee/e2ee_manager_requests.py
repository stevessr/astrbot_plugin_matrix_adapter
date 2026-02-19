from astrbot.api import logger

from ..constants import (
    M_FORWARDED_ROOM_KEY,
    M_ROOM_ENCRYPTED,
    M_ROOM_KEY_REQUEST,
    MEGOLM_ALGO,
    PREFIX_CURVE25519,
    PREFIX_ED25519,
)


class E2EEManagerRequestsMixin:
    async def _request_new_session(
        self, sender_key: str, sender_user_id: str | None = None
    ):
        """
        当检测到未知一次性密钥时，主动建立新的 Olm 会话

        通过 claim 对方的一次性密钥，创建新的出站 Olm 会话，
        然后发送加密的 m.dummy 消息，通知对方使用新会话通信。

        Args:
            sender_key: 发送者的 curve25519 密钥
            sender_user_id: 可选的发送者用户 ID（如果已知，可用于查询设备）
        """
        import secrets

        try:
            # 查找拥有这个 sender_key 的用户和设备
            result = await self._find_device_by_sender_key(sender_key, sender_user_id)

            if not result:
                logger.warning(
                    f"无法找到 sender_key {sender_key[:8]}... 对应的设备，"
                    "无法请求新会话"
                )
                return

            target_user, target_device = result
            logger.info(f"尝试与 {target_user}/{target_device} 建立新的 Olm 会话")

            # 1. 获取对方设备的身份密钥
            resp = await self.client.query_keys({target_user: []})
            devices = resp.get("device_keys", {}).get(target_user, {})
            device_info = devices.get(target_device, {})
            their_curve_key = device_info.get("keys", {}).get(
                f"{PREFIX_CURVE25519}{target_device}"
            )

            if not their_curve_key:
                logger.warning(
                    f"无法获取 {target_user}/{target_device} 的 curve25519 密钥"
                )
                # 回退到发送未加密的 m.dummy
                txn_id = secrets.token_hex(16)
                await self.client.send_to_device(
                    "m.dummy",
                    {target_user: {target_device: {}}},
                    txn_id,
                )
                logger.info(f"已向 {target_user}/{target_device} 发送未加密的 m.dummy")
                return

            # 2. Claim 对方的一次性密钥
            claim_resp = await self.client.claim_keys(
                {target_user: {target_device: "signed_curve25519"}}
            )
            one_time_keys = (
                claim_resp.get("one_time_keys", {})
                .get(target_user, {})
                .get(target_device, {})
            )

            if not one_time_keys:
                logger.warning(f"无法获取 {target_user}/{target_device} 的一次性密钥")
                # 回退到发送未加密的 m.dummy
                txn_id = secrets.token_hex(16)
                await self.client.send_to_device(
                    "m.dummy",
                    {target_user: {target_device: {}}},
                    txn_id,
                )
                logger.info(
                    f"已向 {target_user}/{target_device} 发送未加密的 m.dummy（无可用一次性密钥）"
                )
                return

            # 获取一个可用的一次性密钥
            otk_key_id, otk_data = next(iter(one_time_keys.items()), (None, None))
            if not otk_key_id:
                logger.warning(f"未找到 {target_user}/{target_device} 的一次性密钥条目")
                txn_id = secrets.token_hex(16)
                await self.client.send_to_device(
                    "m.dummy",
                    {target_user: {target_device: {}}},
                    txn_id,
                )
                return
            their_one_time_key = (
                otk_data.get("key") if isinstance(otk_data, dict) else otk_data
            )
            if not their_one_time_key:
                logger.warning(
                    f"{target_user}/{target_device} 的一次性密钥内容为空，回退发送 m.dummy"
                )
                txn_id = secrets.token_hex(16)
                await self.client.send_to_device(
                    "m.dummy",
                    {target_user: {target_device: {}}},
                    txn_id,
                )
                return

            logger.debug(f"获取到一次性密钥：{otk_key_id}")

            # 3. 创建新的出站 Olm 会话
            try:
                session = self._olm.create_outbound_session(
                    their_curve_key, their_one_time_key
                )
                logger.info(f"成功创建与 {target_user}/{target_device} 的新 Olm 会话")
            except Exception as session_e:
                logger.error(f"创建 Olm 会话失败：{session_e}")
                # 回退到发送未加密的 m.dummy
                txn_id = secrets.token_hex(16)
                await self.client.send_to_device(
                    "m.dummy",
                    {target_user: {target_device: {}}},
                    txn_id,
                )
                return

            # 4. 使用新会话发送加密的 m.dummy 消息
            try:
                # m.dummy 内容为空
                dummy_content = {}
                encrypted = self._olm.encrypt_olm(
                    their_curve_key,
                    dummy_content,
                    session=session,
                    recipient_user_id=target_user,
                    event_type="m.dummy",
                )

                txn_id = secrets.token_hex(16)
                await self.client.send_to_device(
                    "m.room.encrypted",
                    {target_user: {target_device: encrypted}},
                    txn_id,
                )

                logger.info(
                    f"已向 {target_user}/{target_device} 发送加密的 m.dummy，新会话已建立"
                )
                logger.info("提示：对方客户端应该会自动使用新会话重新发送消息")

            except Exception as encrypt_e:
                logger.error(f"发送加密 m.dummy 失败：{encrypt_e}")
                # 回退到发送未加密的 m.dummy
                txn_id = secrets.token_hex(16)
                await self.client.send_to_device(
                    "m.dummy",
                    {target_user: {target_device: {}}},
                    txn_id,
                )

        except Exception as e:
            logger.warning(f"建立新会话失败：{e}")
            # 最后尝试发送未加密的 m.dummy
            try:
                if result:
                    target_user, target_device = result
                    txn_id = secrets.token_hex(16)
                    await self.client.send_to_device(
                        "m.dummy",
                        {target_user: {target_device: {}}},
                        txn_id,
                    )
                    logger.info(
                        f"已向 {target_user}/{target_device} 发送未加密的 m.dummy（回退）"
                    )
            except Exception:
                pass

    async def _request_room_key(
        self,
        room_id: str,
        session_id: str,
        sender_key: str | None,
        sender_user_id: str,
    ):
        """
        发送 m.room_key_request 请求密钥

        Args:
            room_id: 房间 ID
            session_id: 会话 ID
            sender_key: 发送者的 curve25519 密钥
            sender_user_id: 发送者用户 ID
        """
        import secrets

        try:
            request_id = secrets.token_hex(16)

            # 构造 m.room_key_request 内容
            content = {
                "action": "request",
                "body": {
                    "algorithm": MEGOLM_ALGO,
                    "room_id": room_id,
                    "sender_key": sender_key or "",
                    "session_id": session_id,
                },
                "request_id": request_id,
                "requesting_device_id": self.device_id,
            }

            # 发送给所有自己的设备
            txn_id = secrets.token_hex(16)
            await self.client.send_to_device(
                M_ROOM_KEY_REQUEST,
                {self.user_id: {"*": content}},  # * 表示所有设备
                txn_id,
            )

            # 也发送给消息发送者的设备
            if sender_user_id and sender_user_id != self.user_id:
                txn_id2 = secrets.token_hex(16)
                await self.client.send_to_device(
                    M_ROOM_KEY_REQUEST,
                    {sender_user_id: {"*": content}},
                    txn_id2,
                )

            logger.info(
                f"已发送密钥请求：room={room_id[:16]}... session={session_id[:8]}..."
            )

        except Exception as e:
            logger.warning(f"发送密钥请求失败：{e}")

    async def respond_to_key_request(
        self,
        sender: str,
        requesting_device_id: str,
        room_id: str,
        session_id: str,
        sender_key: str,
    ):
        """
        响应来自其他设备的密钥请求

        只有同一用户的已验证设备才会收到响应。

        Args:
            sender: 请求者用户 ID
            requesting_device_id: 请求者设备 ID
            room_id: 房间 ID
            session_id: 会话 ID
            sender_key: 发送者密钥
        """
        if not self._olm or not self._initialized:
            logger.warning("未初始化，无法响应密钥请求")
            return

        try:
            # 只响应同一用户的请求（安全限制）
            if sender != self.user_id:
                logger.debug(f"忽略来自其他用户的密钥请求：{sender}")
                return

            # 不响应自己设备的请求
            if requesting_device_id == self.device_id:
                logger.debug("忽略来自自己的密钥请求")
                return

            # 获取请求者的设备密钥信息
            resp = await self.client.query_keys({sender: []})
            devices = resp.get("device_keys", {}).get(sender, {})
            device_info = devices.get(requesting_device_id, {})
            curve_key = device_info.get("keys", {}).get(
                f"{PREFIX_CURVE25519}{requesting_device_id}"
            )
            ed25519_key = device_info.get("keys", {}).get(
                f"{PREFIX_ED25519}{requesting_device_id}"
            )

            if not curve_key:
                logger.warning(
                    f"无法获取设备 {sender}/{requesting_device_id} 的 Curve25519 密钥"
                )
                return

            # 验证请求设备是否已被信任
            # 检查方式：1. 通过 SAS 验证存储 2. 通过交叉签名验证
            device_verified = False

            # 1. 检查 SAS 验证存储
            if self._verification and ed25519_key:
                device_store = getattr(self._verification, "device_store", None)
                if device_store and device_store.is_trusted(
                    sender, requesting_device_id, ed25519_key
                ):
                    device_verified = True
                    logger.debug(f"设备 {requesting_device_id} 已通过 SAS 验证")

            # 2. 检查交叉签名验证
            if (
                not device_verified
                and self._cross_signing
                and self._cross_signing._self_signing_key
            ):
                signatures = device_info.get("signatures", {}).get(sender, {})
                # 检查是否有自签名密钥的签名（使用完整公钥作为 key ID）
                self_signing_key_id = f"ed25519:{self._cross_signing._self_signing_key}"
                if self_signing_key_id in signatures:
                    device_verified = True
                    logger.debug(f"设备 {requesting_device_id} 已通过交叉签名验证")

            # 3. 如果启用了 TOFU（首次使用信任），可以放宽验证要求
            if not device_verified and self.trust_on_first_use:
                logger.info(
                    f"设备 {requesting_device_id} 未验证，但 TOFU 已启用，允许转发密钥"
                )
                device_verified = True

            if not device_verified:
                logger.warning(
                    f"拒绝向未验证的设备 {requesting_device_id} 转发密钥 "
                    f"(session={session_id[:8]}...)"
                )
                return

            # 获取请求的 Megolm 会话
            session = self._olm.get_megolm_inbound_session(session_id)
            if not session:
                logger.debug(f"没有请求的会话：session={session_id[:8]}...")
                return

            # 导出会话密钥
            try:
                exported_key = session.export_at_first_known_index()
                logger.info(
                    f"导出会话密钥：session={session_id[:8]}..., "
                    f"first_index={session.first_known_index}"
                )
            except Exception as e:
                logger.warning(f"导出会话密钥失败：{e}")
                return

            # 构造 m.forwarded_room_key 内容
            # 根据 Matrix 规范，type 不应包含在内容中（它是事件类型）
            forwarded_room_key = {
                "algorithm": MEGOLM_ALGO,
                "room_id": room_id,
                "sender_key": sender_key,
                "session_id": session_id,
                "session_key": exported_key.to_base64(),
                "sender_claimed_ed25519_key": str(self._olm.ed25519_key),
                "forwarding_curve25519_key_chain": [],
            }

            # 使用 Olm 加密并包装，指定事件类型为 m.forwarded_room_key
            encrypted_content = self._olm.encrypt_olm(
                curve_key,
                forwarded_room_key,
                recipient_user_id=sender,
                event_type=M_FORWARDED_ROOM_KEY,
            )

            import secrets

            txn_id = secrets.token_hex(16)
            await self.client.send_to_device(
                M_ROOM_ENCRYPTED,
                {sender: {requesting_device_id: encrypted_content}},
                txn_id,
            )

            logger.info(
                f"已加密转发密钥：session={session_id[:8]}... -> device={requesting_device_id}"
            )

        except Exception as e:
            logger.warning(f"响应密钥请求失败：{e}")

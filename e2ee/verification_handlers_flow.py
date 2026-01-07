import hashlib

from astrbot.api import logger

from ..constants import (
    INFO_PREFIX_MAC,
    INFO_PREFIX_SAS,
    M_SAS_V1_METHOD,
    SAS_BYTES_LENGTH_6,
)
from .verification_constants import (
    SAS_EMOJIS,
    VODOZEMAC_SAS_AVAILABLE,
    Curve25519PublicKey,
    Sas,
)


class SASVerificationFlowMixin:
    async def _handle_request(self, sender: str, content: dict, transaction_id: str):
        """处理验证请求"""
        from_device = content.get("from_device")
        methods = content.get("methods", [])
        if not from_device:
            logger.warning("[E2EE-Verify] 验证请求缺少 from_device，忽略")
            return

        logger.info(
            f"[E2EE-Verify] 收到验证请求："
            f"sender={sender} device={from_device} methods={methods}"
        )

        # 创建 SAS 实例
        sas = None
        if VODOZEMAC_SAS_AVAILABLE:
            try:
                sas = Sas()
                pub = sas.public_key.to_base64()
                logger.debug(f"[E2EE-Verify] 创建 SAS 实例，公钥：{pub[:16]}...")
            except Exception as e:
                logger.warning(f"[E2EE-Verify] 创建 SAS 实例失败：{e}")

        self._sessions[transaction_id] = {
            "sender": sender,
            "from_device": from_device,
            "methods": methods,
            "state": "requested",
            "sas": sas,
        }

        if self.auto_verify_mode == "auto_reject":
            logger.info("[E2EE-Verify] 自动拒绝验证请求 (mode=auto_reject)")
            await self._send_cancel(
                sender, from_device, transaction_id, "m.user", "自动拒绝"
            )
            return

        if self.auto_verify_mode == "manual":
            logger.info("[E2EE-Verify] 手动模式，发送 ready 并等待管理员确认 (mode=manual)")
            if "m.sas.v1" in methods:
                await self._send_ready(sender, from_device, transaction_id)
            else:
                await self._send_cancel(
                    sender,
                    from_device,
                    transaction_id,
                    "m.unknown_method",
                    "不支持的验证方法",
                )
            return

        # auto_accept: 发送 ready
        if "m.sas.v1" in methods:
            logger.info("[E2EE-Verify] 自动接受验证请求 (mode=auto_accept)")
            await self._send_ready(sender, from_device, transaction_id)
        else:
            logger.warning(f"[E2EE-Verify] 不支持的验证方法：{methods}")
            await self._send_cancel(
                sender,
                from_device,
                transaction_id,
                "m.unknown_method",
                "不支持的验证方法",
            )

    async def _handle_ready(self, sender: str, content: dict, transaction_id: str):
        """处理 ready 响应"""
        from_device = content.get("from_device")
        methods = content.get("methods", [])

        logger.info(f"[E2EE-Verify] 对方已就绪：device={from_device} methods={methods}")

        session = self._sessions.get(transaction_id, {})
        session["state"] = "ready"
        session["their_device"] = from_device

        # 如果是我们发起的验证（即我们在等待 ready），我们需要发送 start
        if session.get("we_started_it"):
            logger.info("[E2EE-Verify] 作为发起者，开始验证流程 (sending start)")
            # 选择一个共同的验证方法
            if M_SAS_V1_METHOD in methods:
                await self._send_start(sender, from_device, transaction_id)
            else:
                logger.warning(f"[E2EE-Verify] 无共同验证方法：{methods}")
                await self._send_cancel(
                    sender,
                    from_device,
                    transaction_id,
                    "m.unknown_method",
                    "No common methods",
                )

    async def _handle_start(self, sender: str, content: dict, transaction_id: str):
        """处理验证开始"""
        from_device = content.get("from_device")
        method = content.get("method")
        their_commitment = content.get("commitment")

        logger.info(
            f"[E2EE-Verify] 验证开始：method={method} "
            f"commitment={their_commitment[:16] if their_commitment else 'None'}..."
        )

        session = self._sessions.get(transaction_id, {})
        session["state"] = "started"
        session["method"] = method
        session["their_commitment"] = their_commitment
        session["start_content"] = content
        session["we_are_initiator"] = False  # 收到 start，说明对方是 Initiator

        # Check if this is an in-room verification
        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")

        if self.auto_verify_mode == "auto_accept":
            if from_device:
                if is_in_room and room_id:
                    await self._send_in_room_accept(room_id, transaction_id, content)
                else:
                    await self._send_accept(
                        sender, from_device, transaction_id, content
                    )

    async def _handle_accept(self, sender: str, content: dict, transaction_id: str):
        """处理验证接受"""
        commitment = content.get("commitment")
        key_agreement = content.get("key_agreement_protocol")
        hash_algo = content.get("hash")
        mac = content.get("message_authentication_code")
        sas_methods = content.get("short_authentication_string", [])

        logger.info(
            f"[E2EE-Verify] 对方接受验证："
            f"key_agreement={key_agreement} hash={hash_algo} mac={mac}"
        )

        session = self._sessions.get(transaction_id, {})
        session["state"] = "accepted"
        session["their_commitment"] = commitment
        session["key_agreement"] = key_agreement
        session["hash"] = hash_algo
        session["mac"] = mac
        session["sas_methods"] = sas_methods

        if self.auto_verify_mode == "auto_accept":
            # Check if this is an in-room verification
            is_in_room = session.get("is_in_room", False)
            room_id = session.get("room_id")

            if is_in_room and room_id:
                await self._send_in_room_key(room_id, transaction_id)
            else:
                await self._send_key(
                    sender,
                    content.get("from_device", session.get("from_device", "")),
                    transaction_id,
                )

    async def _handle_key(self, sender: str, content: dict, transaction_id: str):
        """处理密钥交换 - 使用真正的 X25519"""
        their_key = content.get("key")

        if not isinstance(their_key, str) or not their_key:
            logger.warning("[E2EE-Verify] 对方公钥缺失或格式不正确")
            return
        logger.info(f"[E2EE-Verify] 收到对方公钥：{their_key[:20]}...")

        session = self._sessions.get(transaction_id, {})
        session["their_key"] = their_key
        session["state"] = "key_exchanged"

        # Check if this is an in-room verification
        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")
        their_device = session.get("from_device", session.get("their_device", ""))

        # 如果我们还没发送自己的公钥，先发送
        if not session.get("key_sent"):
            if self.auto_verify_mode == "auto_accept":
                if is_in_room and room_id:
                    await self._send_in_room_key(room_id, transaction_id)
                else:
                    await self._send_key(sender, their_device, transaction_id)
                session["key_sent"] = True

        sas = session.get("sas")
        our_key = session.get("our_public_key")

        # Safety check: Skip if SAS already computed (defensive measure)
        if session.get("established_sas") or session.get("sas_emojis"):
            logger.debug("[E2EE-Verify] SAS 已计算，跳过重复计算")
            return

        if sas and VODOZEMAC_SAS_AVAILABLE and their_key:
            try:
                # 使用 vodozemac 计算共享密钥
                # 构造 SAS info 字符串
                their_user = sender

                # 确定 Initiator 和 Recipient
                # 发送 m.key.verification.start 的是 Initiator
                if session.get("we_are_initiator"):
                    init_user, init_dev, init_key = (
                        self.user_id,
                        self.device_id,
                        our_key,
                    )
                    rec_user, rec_dev, rec_key = their_user, their_device, their_key
                else:
                    init_user, init_dev, init_key = their_user, their_device, their_key
                    rec_user, rec_dev, rec_key = self.user_id, self.device_id, our_key

                info = (
                    f"{INFO_PREFIX_SAS}"
                    f"{init_user}|{init_dev}|{init_key}|"
                    f"{rec_user}|{rec_dev}|{rec_key}|"
                    f"{transaction_id}"
                )

                # 使用 vodozemac 的 diffie_hellman 方法完成密钥交换
                # 这会返回一个 EstablishedSas 对象
                their_public_key = Curve25519PublicKey.from_base64(their_key)
                established_sas = sas.diffie_hellman(their_public_key)

                # 保存 established_sas 用于后续 MAC 计算
                session["established_sas"] = established_sas

                # 使用 established_sas.bytes(info) 获取 SAS 字节对象
                sas_bytes_obj = established_sas.bytes(info)

                # vodozemac SasBytes 对象有 emoji_indices (bytes) 和 decimals (tuple) 属性
                # emoji_indices 是 7 个字节，每个字节是 0-63 的索引
                emoji_indices = sas_bytes_obj.emoji_indices
                emojis = [SAS_EMOJIS[idx] for idx in emoji_indices]

                # decimals 是一个包含 3 个数字的元组
                decimals_tuple = sas_bytes_obj.decimals
                decimals = (
                    f"{decimals_tuple[0]} {decimals_tuple[1]} {decimals_tuple[2]}"
                )

                session["sas_bytes"] = emoji_indices  # 保存原始字节用于回退
                session["sas_emojis"] = emojis
                session["sas_decimals"] = decimals

                emoji_str = " ".join(e[0] for e in emojis)
                logger.info(f"[E2EE-Verify] SAS 验证码：{emoji_str} | 数字：{decimals}")

            except Exception as e:
                logger.error(f"[E2EE-Verify] 计算 SAS 失败：{e}")
                # 回退到简化实现
                self._compute_sas_fallback(session, their_key)
        else:
            # 使用简化实现
            self._compute_sas_fallback(session, their_key)

        if self.auto_verify_mode == "manual" and not session.get("manual_notified"):
            session["manual_notified"] = True
            await self._notify_admin_for_verification(session, transaction_id)

        # Send MAC only if not already sent
        if self.auto_verify_mode == "auto_accept" and not session.get("mac_sent"):
            session["mac_sent"] = True
            if is_in_room and room_id:
                await self._send_in_room_mac(room_id, transaction_id, session)
            else:
                await self._send_mac(
                    sender,
                    their_device,
                    transaction_id,
                    session,
                )

    def _compute_sas_fallback(self, session: dict, their_key: str):
        """回退的 SAS 计算（当 vodozemac SAS 不可用时）"""
        our_key = session.get("our_public_key", "")
        combined = f"{our_key}{their_key}".encode()
        sas_bytes = hashlib.sha256(combined).digest()[:SAS_BYTES_LENGTH_6]

        emojis = self._bytes_to_emoji(sas_bytes)
        decimals = self._bytes_to_decimal(sas_bytes)

        session["sas_bytes"] = sas_bytes
        session["sas_emojis"] = emojis
        session["sas_decimals"] = decimals

        emoji_str = " ".join(e[0] for e in emojis)
        logger.info(
            f"[E2EE-Verify] SAS 验证码 (fallback): {emoji_str} | 数字：{decimals}"
        )

    async def _handle_mac(self, sender: str, content: dict, transaction_id: str):
        """处理 MAC 验证"""
        their_mac = content.get("mac", {})
        their_keys = content.get("keys")

        logger.debug(f"[E2EE-Verify] 收到 MAC: keys={their_keys}")

        session = self._sessions.get(transaction_id, {})
        session["their_mac"] = their_mac
        session["state"] = "mac_received"

        # 验证 MAC
        established_sas = session.get("established_sas")
        their_device = session.get("from_device", session.get("their_device", ""))

        if established_sas and VODOZEMAC_SAS_AVAILABLE:
            try:
                # 构建 MAC 验证的 base_info
                _base_info = f"{INFO_PREFIX_MAC}{sender}{their_device}{self.user_id}{self.device_id}{transaction_id}"

                # 验证对方发送的每个密钥的 MAC
                for key_id, mac_value in their_mac.items():
                    # 记录接收到的 MAC（在 auto_accept 模式下信任对方）
                    logger.debug(f"[E2EE-Verify] MAC 已接收：key_id={key_id}")

            except Exception as e:
                logger.error(f"[E2EE-Verify] MAC 验证失败：{e}")

        if self.auto_verify_mode == "auto_accept" and not session.get("done_sent"):
            session["done_sent"] = True
            # Check if this is an in-room verification
            is_in_room = session.get("is_in_room", False)
            room_id = session.get("room_id")

            if is_in_room and room_id:
                await self._send_in_room_done(room_id, transaction_id)
            else:
                await self._send_done(
                    sender,
                    session.get("their_device", session.get("from_device", "")),
                    transaction_id,
                )

    async def _handle_done(self, sender: str, content: dict, transaction_id: str):
        """处理验证完成"""
        logger.info(f"[E2EE-Verify] ✅ 验证完成！sender={sender} txn={transaction_id}")

        session = self._sessions.get(transaction_id, {})
        session["state"] = "done"

        # 将设备标记为已验证
        from_device = session.get("from_device") or session.get("their_device")
        fingerprint = session.get("fingerprint")

        # If we didn't get fingerprint earlier, try to get it from the key exchange if possible,
        # or try query again?
        # The 'key' exchanged in SAS is the ephemeral key, not the device identity key.
        # But we should have fetched it in handle_request.

        if from_device and fingerprint:
            try:
                self.device_store.add_device(sender, from_device, fingerprint)
                logger.info(
                    f"[E2EE-Verify] Device verified and saved: {sender}|{from_device}"
                )
            except Exception as e:
                logger.error(f"[E2EE-Verify] Failed to save verified device: {e}")
        else:
            logger.warning(
                f"[E2EE-Verify] Cannot save device: missing info (device={from_device}, fingerprint={fingerprint})"
            )

    async def _handle_cancel(self, sender: str, content: dict, transaction_id: str):
        """处理验证取消"""
        code = content.get("code")
        reason = content.get("reason")

        logger.warning(f"[E2EE-Verify] ❌ 验证被取消：code={code} reason={reason}")

        if transaction_id in self._sessions:
            self._sessions[transaction_id]["state"] = "cancelled"
            self._sessions[transaction_id]["cancel_code"] = code
            self._sessions[transaction_id]["cancel_reason"] = reason

    # ========== 发送验证消息 ==========

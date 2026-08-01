import base64
import hashlib
import hmac

from astrbot.api import logger

from ...constants import (
    INFO_PREFIX_MAC,
    INFO_PREFIX_SAS,
    PREFIX_ED25519,
)
from .constants import (
    SAS_EMOJIS,
    VODOZEMAC_SAS_AVAILABLE,
    Curve25519PublicKey,
)
from .crypto_utils import (
    _canonical_json,
    _compute_hkdf,
    _encode_unpadded_base64,
)


class SASVerificationFlowKeyMixin:
    async def _handle_key(self, sender: str, content: dict, transaction_id: str):
        """处理密钥交换 - 使用真正的 X25519"""
        their_key = content.get("key")

        if not isinstance(their_key, str) or not their_key:
            logger.warning("[E2EE-Verify] 对方公钥缺失或格式不正确")
            return
        logger.info("[E2EE-Verify] 收到对方公钥")

        session = self._sessions.get(transaction_id, {})

        # 根据 Matrix 规范验证 commitment
        # commitment = SHA256(公钥 || canonical_json(start_content))
        # 参考：https://spec.matrix.org/latest/client-server-api/#sas-verification
        their_commitment = session.get("their_commitment")
        start_content = session.get("start_content")
        if their_commitment and start_content and session.get("we_are_initiator"):
            # The start sender validates the accept sender's commitment once it
            # receives that sender's public key. Hash the exact start *content*
            # object and encode the digest as unpadded Base64 (Matrix v1.19).
            combined = (their_key + _canonical_json(start_content)).encode("utf-8")
            computed = _encode_unpadded_base64(hashlib.sha256(combined).digest())

            if computed != their_commitment:
                logger.warning(
                    "[E2EE-Verify] Commitment 验证失败！"
                    f"expected={(their_commitment if isinstance(their_commitment, str) else '')[:16]}... "
                    f"computed={(computed or '')[:16]}..."
                )
                # 根据规范，commitment 不匹配应该取消验证
                if session.get("is_in_room") and session.get("room_id"):
                    await self._send_in_room_cancel(
                        session["room_id"],
                        transaction_id,
                        "m.mismatched_commitment",
                        "Commitment verification failed",
                    )
                else:
                    their_device = session.get(
                        "from_device", session.get("their_device", "")
                    )
                    await self._send_cancel(
                        sender,
                        their_device,
                        transaction_id,
                        "m.mismatched_commitment",
                        "Commitment verification failed",
                    )
                return
            else:
                logger.info("[E2EE-Verify] ✅ Commitment 验证通过")

        session["their_key"] = their_key
        session["state"] = "key_exchanged"

        # Check if this is an in-room verification
        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")
        their_device = session.get("from_device", session.get("their_device", ""))

        # 如果我们还没发送自己的公钥，先发送
        if not session.get("key_sent"):
            if self.auto_verify_mode in ("auto_accept", "manual"):
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
                if len(decimals_tuple) >= 3:
                    decimals = (
                        f"{decimals_tuple[0]} {decimals_tuple[1]} {decimals_tuple[2]}"
                    )
                else:
                    decimals = " ".join(map(str, decimals_tuple))

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

    async def _handle_mac(self, sender: str, content: dict, transaction_id: str):
        """处理 MAC 验证"""
        their_mac = content.get("mac") or {}
        their_keys = content.get("keys")

        logger.debug(f"[E2EE-Verify] 收到 MAC: keys={their_keys}")

        session = self._sessions.get(transaction_id, {})
        session["their_mac"] = their_mac
        session["state"] = "mac_received"

        established_sas = session.get("established_sas")
        their_device = session.get("from_device", session.get("their_device", ""))
        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")
        sas_bytes = session.get("sas_bytes", b"\x00" * 32)

        async def _cancel_mac_verification(reason: str):
            logger.warning(f"[E2EE-Verify] MAC 校验失败：{reason}")
            session["state"] = "cancelled"
            session["cancel_code"] = "m.key_mismatch"
            session["cancel_reason"] = reason
            if is_in_room and room_id:
                await self._send_in_room_cancel(
                    room_id,
                    transaction_id,
                    "m.key_mismatch",
                    reason,
                )
            else:
                await self._send_cancel(
                    sender,
                    their_device,
                    transaction_id,
                    "m.key_mismatch",
                    reason,
                )

        if not isinstance(their_mac, dict) or not their_mac:
            await _cancel_mac_verification("MAC verification failed")
            return

        available_keys: dict[str, str] = {}
        fingerprint = session.get("fingerprint")
        if fingerprint and their_device:
            available_keys[f"{PREFIX_ED25519}{their_device}"] = fingerprint

        master_key = session.get("master_key")
        master_key_id = session.get("master_key_id")
        if master_key_id and master_key:
            available_keys[master_key_id] = master_key

        if their_device and (
            f"{PREFIX_ED25519}{their_device}" not in available_keys or not master_key_id
        ):
            try:
                resp = await self.client.query_keys({sender: []})
                devices = resp.get("device_keys") or {}
                user_devices = devices.get(sender) or {}
                device_info = user_devices.get(their_device) or {}
                keys = device_info.get("keys") or {}
                fingerprint = keys.get(f"{PREFIX_ED25519}{their_device}")
                if fingerprint:
                    session["fingerprint"] = fingerprint
                    available_keys[f"{PREFIX_ED25519}{their_device}"] = fingerprint

                master_key_obj = (resp.get("master_keys") or {}).get(sender) or {}
                master_keys = master_key_obj.get("keys") or {}
                if master_keys:
                    fetched_master_key_id, fetched_master_key = next(
                        iter(master_keys.items())
                    )
                    session["master_key_id"] = fetched_master_key_id
                    session["master_key"] = fetched_master_key
                    available_keys[fetched_master_key_id] = fetched_master_key
            except Exception as e:
                logger.warning(f"[E2EE-Verify] 查询 MAC 校验密钥失败：{e}")

        if not their_device or not available_keys:
            await _cancel_mac_verification("MAC verification failed")
            return

        key_ids = sorted(their_mac.keys())
        if not key_ids:
            await _cancel_mac_verification("MAC verification failed")
            return

        for key_id in key_ids:
            if key_id not in available_keys:
                await _cancel_mac_verification("MAC verification failed")
                return
            if not isinstance(their_mac.get(key_id), str):
                await _cancel_mac_verification("MAC verification failed")
                return

        base_info = f"{INFO_PREFIX_MAC}{sender}{their_device}{self.user_id}{self.device_id}{transaction_id}"
        key_ids_csv = ",".join(key_ids)

        try:
            if established_sas:
                expected_mac_map = {
                    key_id: established_sas.calculate_mac(
                        available_keys[key_id], (base_info + key_id)
                    )
                    for key_id in key_ids
                }
                expected_keys_mac = established_sas.calculate_mac(
                    key_ids_csv, (base_info + "KEY_IDS")
                )
            else:
                expected_mac_map = {
                    key_id: base64.b64encode(
                        _compute_hkdf(sas_bytes, b"", available_keys[key_id].encode())
                    ).decode()
                    for key_id in key_ids
                }
                expected_keys_mac = base64.b64encode(
                    hashlib.sha256(key_ids_csv.encode()).digest()
                ).decode()
        except Exception as e:
            logger.error(f"[E2EE-Verify] MAC 计算失败：{e}")
            await _cancel_mac_verification("MAC verification failed")
            return

        if not isinstance(their_keys, str):
            await _cancel_mac_verification("MAC verification failed")
            return

        for key_id in key_ids:
            actual_mac = their_mac.get(key_id)
            if not hmac.compare_digest(actual_mac, expected_mac_map[key_id]):
                await _cancel_mac_verification("MAC verification failed")
                return

        if not hmac.compare_digest(their_keys, expected_keys_mac):
            await _cancel_mac_verification("MAC verification failed")
            return

        session["mac_verified"] = True
        logger.info(
            "[E2EE-Verify] ✅ MAC 校验通过："
            f"device={self._mask_identifier(their_device)}"
        )

        if self.auto_verify_mode == "auto_accept" and not session.get("done_sent"):
            session["done_sent"] = True
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
        logger.info(
            "[E2EE-Verify] ✅ 验证完成！"
            f"sender={self._mask_identifier(sender)} "
            f"txn={self._mask_txn_id(transaction_id)}"
        )

        session = self._sessions.get(transaction_id, {})
        qr_verified = bool(session.get("qr_confirmed"))
        if session.get("state") == "cancelled" or (
            not session.get("mac_verified") and not qr_verified
        ):
            logger.warning("[E2EE-Verify] 忽略 done：会话已取消或 MAC 尚未验证通过")
            return

        target_device = session.get("from_device") or session.get("their_device")
        if (
            session.get("qr_scanned_by_us")
            and target_device
            and not session.get("done_sent")
        ):
            session["done_sent"] = True
            is_in_room = session.get("is_in_room", False)
            room_id = session.get("room_id")
            if is_in_room and room_id:
                await self._send_in_room_done(room_id, transaction_id)
            else:
                await self._send_done(sender, target_device, transaction_id)
        session["state"] = "done"

        # 将设备标记为已验证
        from_device = target_device
        fingerprint = session.get("fingerprint")

        # If we didn't get fingerprint earlier, try to get it from the key exchange if possible,
        # or try query again?
        # The 'key' exchanged in SAS is the ephemeral key, not the device identity key.
        # But we should have fetched it in handle_request.

        if from_device and fingerprint:
            try:
                self.device_store.add_device(sender, from_device, fingerprint)
                logger.info(
                    "[E2EE-Verify] Device verified and saved: "
                    f"{self._mask_identifier(sender)}|"
                    f"{self._mask_identifier(from_device)}"
                )
            except Exception as e:
                logger.error(f"[E2EE-Verify] Failed to save verified device: {e}")
        else:
            logger.warning(
                "[E2EE-Verify] Cannot save device: missing info "
                f"(device={self._mask_identifier(from_device)}, "
                f"has_fingerprint={bool(fingerprint)})"
            )

        e2ee_manager = getattr(self, "e2ee_manager", None)
        if e2ee_manager and sender == self.user_id:
            publish_target = from_device or session.get("their_device")

            if publish_target:
                try:
                    await e2ee_manager.publish_trusted_device(sender, publish_target)
                except Exception as e:
                    logger.warning(
                        "[E2EE-Verify] 发布设备信任失败："
                        f"device={self._mask_identifier(publish_target)} err={e}"
                    )
            try:
                await e2ee_manager.request_missing_secrets_after_verification(sender)
            except Exception as e:
                logger.warning(f"[E2EE-Verify] 验证后请求缺失秘密失败：{e}")

    async def _handle_cancel(self, sender: str, content: dict, transaction_id: str):
        """处理验证取消"""
        code = content.get("code")
        reason = content.get("reason")

        logger.warning(f"[E2EE-Verify] ❌ 验证被取消：code={code} reason={reason}")

        if transaction_id in self._sessions:
            self._sessions[transaction_id]["state"] = "cancelled"
            self._sessions[transaction_id]["cancel_code"] = code
            self._sessions[transaction_id]["cancel_reason"] = reason

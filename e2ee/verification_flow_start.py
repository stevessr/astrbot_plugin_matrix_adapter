import hmac

from astrbot.api import logger

from ..constants import (
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    M_SAS_V1_METHOD,
    PREFIX_ED25519,
)
from .verification_constants import (
    VODOZEMAC_SAS_AVAILABLE,
    Sas,
)


class SASVerificationFlowStartMixin:
    async def _handle_request(self, sender: str, content: dict, transaction_id: str):
        """处理验证请求"""
        from_device = content.get("from_device")
        methods = content.get("methods", [])
        if not from_device:
            logger.warning("[E2EE-Verify] 验证请求缺少 from_device，忽略")
            return

        logger.info(
            f"[E2EE-Verify] 收到验证请求："
            f"sender={self._mask_identifier(sender)} "
            f"device={self._mask_identifier(from_device)} methods={methods}"
        )

        # 创建 SAS 实例
        sas = None
        if VODOZEMAC_SAS_AVAILABLE:
            try:
                sas = Sas()
                logger.debug("[E2EE-Verify] 创建 SAS 实例")
            except Exception as e:
                logger.warning(f"[E2EE-Verify] 创建 SAS 实例失败：{e}")

        self._sessions[transaction_id] = {
            "sender": sender,
            "from_device": from_device,
            "methods": methods,
            "state": "requested",
            "sas": sas,
        }

        session = self._sessions[transaction_id]
        try:
            resp = await self.client.query_keys({sender: []})
            devices = resp.get("device_keys") or {}
            user_devices = devices.get(sender) or {}
            device_info = user_devices.get(from_device) or {}
            keys = device_info.get("keys") or {}
            fingerprint = keys.get(f"{PREFIX_ED25519}{from_device}")
            if fingerprint:
                session["fingerprint"] = fingerprint
                logger.debug(
                    "[E2EE-Verify] 已获取设备指纹："
                    f"device={self._mask_identifier(from_device)}"
                )
            else:
                logger.warning(
                    "[E2EE-Verify] 未找到设备指纹："
                    f"sender={self._mask_identifier(sender)} "
                    f"device={self._mask_identifier(from_device)}"
                )

            master_key_obj = (resp.get("master_keys") or {}).get(sender) or {}
            master_keys = master_key_obj.get("keys") or {}
            if master_keys:
                master_key_id, master_key = next(iter(master_keys.items()))
                session["master_key_id"] = master_key_id
                session["master_key"] = master_key
        except Exception as e:
            logger.warning(
                "[E2EE-Verify] 查询验证设备指纹失败："
                f"sender={self._mask_identifier(sender)} "
                f"device={self._mask_identifier(from_device)} err={e}"
            )

        if self.auto_verify_mode == "auto_reject":
            logger.info("[E2EE-Verify] 自动拒绝验证请求 (mode=auto_reject)")
            await self._send_cancel(
                sender, from_device, transaction_id, "m.user", "自动拒绝"
            )
            return

        if self.auto_verify_mode == "manual":
            logger.info(
                "[E2EE-Verify] 手动模式，发送 ready 并等待管理员确认 (mode=manual)"
            )
            if self._supports_method(
                methods, M_SAS_V1_METHOD
            ) or self._can_continue_with_qr(sender, methods):
                await self._send_ready(sender, from_device, transaction_id)
                await self._maybe_prepare_self_verification_qr(
                    sender, from_device, methods, transaction_id
                )
                if (
                    sender == self.user_id
                    and self._supports_method(methods, M_QR_CODE_SHOW_V1_METHOD)
                    and self._supports_method(methods, M_RECIPROCATE_V1_METHOD)
                ):
                    notify_scan = getattr(self, "_notify_admin_to_scan_peer_qr", None)
                    if callable(notify_scan):
                        await notify_scan(
                            self._sessions[transaction_id], transaction_id
                        )
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
        if self._supports_method(
            methods, M_SAS_V1_METHOD
        ) or self._can_continue_with_qr(sender, methods):
            logger.info("[E2EE-Verify] 自动接受验证请求 (mode=auto_accept)")
            await self._send_ready(sender, from_device, transaction_id)
            await self._maybe_prepare_self_verification_qr(
                sender, from_device, methods, transaction_id
            )
            if (
                sender == self.user_id
                and self._supports_method(methods, M_QR_CODE_SHOW_V1_METHOD)
                and self._supports_method(methods, M_RECIPROCATE_V1_METHOD)
            ):
                notify_scan = getattr(self, "_notify_admin_to_scan_peer_qr", None)
                if callable(notify_scan):
                    await notify_scan(self._sessions[transaction_id], transaction_id)
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

        logger.info(
            "[E2EE-Verify] 对方已就绪："
            f"device={self._mask_identifier(from_device)} methods={methods}"
        )

        session = self._sessions.get(transaction_id, {})
        session["state"] = "ready"
        session["their_device"] = from_device

        # 如果是我们发起的验证（即我们在等待 ready），我们需要发送 start
        if session.get("we_started_it"):
            qr_prepared = await self._maybe_prepare_self_verification_qr(
                sender, from_device, methods, transaction_id
            )
            if qr_prepared:
                logger.info("[E2EE-Verify] 作为发起者，优先展示 QR 自验证码")
                return

            if (
                sender == self.user_id
                and self._supports_method(methods, M_QR_CODE_SHOW_V1_METHOD)
                and self._supports_method(methods, M_RECIPROCATE_V1_METHOD)
            ):
                session["state"] = "ready_for_qr_scan"
                logger.info(
                    "[E2EE-Verify] 对端支持展示 QR，等待扫码命令而不自动回退到 SAS"
                )
                notify_scan = getattr(self, "_notify_admin_to_scan_peer_qr", None)
                if callable(notify_scan):
                    await notify_scan(session, transaction_id)
                return

            logger.info("[E2EE-Verify] 作为发起者，开始 SAS 验证流程")
            if self._supports_method(methods, M_SAS_V1_METHOD):
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

        masked_their_commitment = (
            their_commitment[:16] if isinstance(their_commitment, str) else "None"
        )
        logger.info(
            f"[E2EE-Verify] 验证开始：method={method} "
            f"commitment={masked_their_commitment}..."
        )

        session = self._sessions.get(transaction_id, {})
        session["state"] = "started"
        session["method"] = method
        session["their_commitment"] = their_commitment
        session["start_content"] = content
        session["we_are_initiator"] = False  # 收到 start，说明对方是 Initiator

        if method == M_RECIPROCATE_V1_METHOD:
            handled = await self._handle_reciprocate_start(
                sender,
                from_device,
                content,
                transaction_id,
                session,
            )
            if handled:
                return

        # Check if this is an in-room verification
        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")

        if self.auto_verify_mode in ("auto_accept", "manual"):
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
        sas_methods = content.get("short_authentication_string") or []

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

        if self.auto_verify_mode in ("auto_accept", "manual"):
            # Check if this is an in-room verification
            is_in_room = session.get("is_in_room", False)
            room_id = session.get("room_id")
            target_device = (
                content.get("from_device")
                or session.get("their_device")
                or session.get("from_device", "")
            )

            if is_in_room and room_id:
                await self._send_in_room_key(room_id, transaction_id)
            else:
                await self._send_key(sender, target_device, transaction_id)

    async def _handle_reciprocate_start(
        self,
        sender: str,
        from_device: str | None,
        content: dict,
        transaction_id: str,
        session: dict,
    ) -> bool:
        expected_secret = session.get("qr_shared_secret_b64")
        received_secret = content.get("secret")
        if not isinstance(expected_secret, str) or not expected_secret:
            logger.warning("[E2EE-Verify] 收到 reciprocate，但当前会话没有待确认的 QR")
            if from_device:
                await self._send_cancel(
                    sender,
                    from_device,
                    transaction_id,
                    "m.unexpected_message",
                    "No QR code is pending for this verification",
                )
            return True
        if not isinstance(received_secret, str) or not received_secret:
            logger.warning("[E2EE-Verify] 收到 reciprocate，但缺少 secret")
            if from_device:
                await self._send_cancel(
                    sender,
                    from_device,
                    transaction_id,
                    "m.bad_message_format",
                    "Missing reciprocate secret",
                )
            return True
        if not hmac.compare_digest(received_secret, expected_secret):
            logger.warning("[E2EE-Verify] QR reciprocate secret 不匹配")
            if from_device:
                await self._send_cancel(
                    sender,
                    from_device,
                    transaction_id,
                    "m.key_mismatch",
                    "QR shared secret mismatch",
                )
            return True

        session["qr_reciprocated"] = True
        session["qr_confirmed"] = self.auto_verify_mode == "auto_accept"
        session["state"] = "qr_scanned"
        logger.info(
            "[E2EE-Verify] 对端已扫描 QR："
            f"device={self._mask_identifier(from_device)} "
            f"txn={self._mask_txn_id(transaction_id)}"
        )

        if self.auto_verify_mode == "auto_reject":
            if from_device:
                await self._send_cancel(
                    sender, from_device, transaction_id, "m.user", "自动拒绝"
                )
            return True

        if self.auto_verify_mode == "manual":
            notify = getattr(self, "_notify_admin_for_qr_reciprocation", None)
            if callable(notify):
                await notify(session, transaction_id)
            return True

        if not from_device:
            return True

        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")
        if not session.get("done_sent"):
            session["done_sent"] = True
            if is_in_room and room_id:
                await self._send_in_room_done(room_id, transaction_id)
            else:
                await self._send_done(sender, from_device, transaction_id)
        return True

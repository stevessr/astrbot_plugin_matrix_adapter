import base64
import hashlib
import hmac
import json
import secrets

from astrbot.api import logger

from ..constants import (
    INFO_PREFIX_MAC,
    INFO_PREFIX_SAS,
    M_QR_CODE_SCAN_V1_METHOD,
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    M_SAS_V1_METHOD,
    PREFIX_ED25519,
    QR_CODE_HEADER,
    QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER,
    QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER,
    QR_CODE_VERSION,
    SAS_BYTES_LENGTH_6,
)
from .verification_constants import (
    SAS_EMOJIS,
    VODOZEMAC_SAS_AVAILABLE,
    Curve25519PublicKey,
    Sas,
)
from .verification_utils import _compute_hkdf


class SASVerificationFlowMixin:
    @staticmethod
    def _mask_identifier(value: str | None) -> str:
        if not isinstance(value, str) or not value:
            return "<empty>"
        normalized = value.strip()
        if len(normalized) <= 4:
            return "***"
        return f"{normalized[:2]}***{normalized[-2:]}"

    @staticmethod
    def _mask_txn_id(value: str | None) -> str:
        if not isinstance(value, str) or not value:
            return "<empty>"
        normalized = value.strip()
        if len(normalized) <= 8:
            return "***"
        return f"{normalized[:8]}..."

    @staticmethod
    def _supports_method(methods: object, method: str) -> bool:
        if not isinstance(methods, (list, tuple, set)):
            return False
        return method in methods

    @staticmethod
    def _encode_unpadded_base64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_unpadded_base64(data: str) -> bytes:
        normalized = str(data or "").strip()
        if not normalized:
            return b""
        padding = "=" * (-len(normalized) % 4)
        return base64.b64decode(normalized + padding)

    def _get_local_device_ed25519_key(self) -> str | None:
        olm = getattr(self, "olm", None)
        device_key = getattr(olm, "ed25519_key", None)
        if isinstance(device_key, str) and device_key:
            return device_key
        if olm and hasattr(olm, "get_identity_keys"):
            try:
                keys = olm.get_identity_keys() or {}
                key_id = f"{PREFIX_ED25519}{self.device_id}"
                candidate = keys.get(key_id)
                if isinstance(candidate, str) and candidate:
                    return candidate
            except Exception:
                return None
        return None

    @staticmethod
    def _device_trusts_master_key(response: dict, user_id: str, device_id: str) -> bool:
        master_key = (response.get("master_keys") or {}).get(user_id) or {}
        signatures = (master_key.get("signatures") or {}).get(user_id) or {}
        return f"{PREFIX_ED25519}{device_id}" in signatures

    def _can_continue_with_qr(self, sender: str, methods: object) -> bool:
        if sender != self.user_id:
            return False
        can_show_to_peer = self._supports_method(methods, M_QR_CODE_SCAN_V1_METHOD)
        can_scan_peer = self._supports_method(
            methods, M_QR_CODE_SHOW_V1_METHOD
        ) and self._supports_method(methods, M_RECIPROCATE_V1_METHOD)
        return can_show_to_peer or can_scan_peer

    def _build_self_verification_qr_payload(
        self,
        transaction_id: str,
        key1: str,
        key2: str,
        shared_secret: bytes,
        mode: int,
    ) -> bytes:
        return b"".join(
            [
                QR_CODE_HEADER,
                bytes([QR_CODE_VERSION, mode]),
                len(transaction_id).to_bytes(2, "big"),
                transaction_id.encode("ascii"),
                self._decode_unpadded_base64(key1),
                self._decode_unpadded_base64(key2),
                shared_secret,
            ]
        )

    async def _maybe_prepare_self_verification_qr(
        self,
        sender: str,
        peer_device: str | None,
        methods: object,
        transaction_id: str,
    ) -> bool:
        if sender != self.user_id or not peer_device:
            return False
        if not self._supports_method(methods, M_QR_CODE_SCAN_V1_METHOD):
            return False

        session = self._sessions.setdefault(transaction_id, {})
        if session.get("qr_payload"):
            return True

        try:
            response = await self.client.query_keys({sender: []})
            device_keys = (response.get("device_keys") or {}).get(sender) or {}
            peer_device_info = device_keys.get(peer_device) or {}
            peer_keys = peer_device_info.get("keys") or {}
            peer_device_key = peer_keys.get(f"{PREFIX_ED25519}{peer_device}")
            if peer_device_key:
                session["fingerprint"] = peer_device_key

            master_key_obj = (response.get("master_keys") or {}).get(sender) or {}
            master_keys = master_key_obj.get("keys") or {}
            if master_keys:
                master_key_id, master_key = next(iter(master_keys.items()))
                session["master_key_id"] = master_key_id
                session["master_key"] = master_key
            else:
                master_key = None

            current_device_key = self._get_local_device_ed25519_key()
            if not current_device_key or not peer_device_key or not master_key:
                logger.warning(
                    "[E2EE-Verify] QR 自验证准备失败：缺少必要密钥 "
                    f"(current={bool(current_device_key)} peer={bool(peer_device_key)} master={bool(master_key)})"
                )
                return False

            if self._device_trusts_master_key(response, sender, self.device_id):
                mode = QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER
                key1, key2 = master_key, peer_device_key
            else:
                mode = QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER
                key1, key2 = current_device_key, master_key

            shared_secret = secrets.token_bytes(16)
            payload = self._build_self_verification_qr_payload(
                transaction_id,
                key1,
                key2,
                shared_secret,
                mode,
            )
            session["qr_mode"] = mode
            session["qr_payload"] = payload
            session["qr_shared_secret"] = shared_secret
            session["qr_shared_secret_b64"] = self._encode_unpadded_base64(
                shared_secret
            )

            build_terminal_qr = getattr(self, "_build_terminal_qr", None)
            if callable(build_terminal_qr):
                session["qr_ascii"] = build_terminal_qr(payload)

            logger.info(
                "[E2EE-Verify] 已生成同账号 QR 自验证码："
                f"device={self._mask_identifier(peer_device)} "
                f"mode=0x{mode:02x} txn={self._mask_txn_id(transaction_id)}"
            )
            qr_ascii = str(session.get("qr_ascii") or "").rstrip()
            if qr_ascii:
                logger.info(
                    "[E2EE-Verify] 请在另一台设备上扫描以下二维码完成验证：\n"
                    f"{qr_ascii}"
                )

            notify_qr = getattr(self, "_notify_admin_for_qr_code", None)
            if callable(notify_qr):
                await notify_qr(session, transaction_id)
            return True
        except Exception as e:
            logger.warning(f"[E2EE-Verify] 准备同账号 QR 自验证失败：{e}")
            return False

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
            if self._supports_method(methods, M_SAS_V1_METHOD) or self._can_continue_with_qr(
                sender, methods
            ):
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
                await self._send_cancel(
                    sender,
                    from_device,
                    transaction_id,
                    "m.unknown_method",
                    "不支持的验证方法",
                )
            return

        # auto_accept: 发送 ready
        if self._supports_method(methods, M_SAS_V1_METHOD) or self._can_continue_with_qr(
            sender, methods
        ):
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
        if their_commitment and start_content and not session.get("we_are_initiator"):
            # 只有非发起方需要验证 commitment（发起方发送 start，接收方发送 accept）
            # start_content 需要去掉可能的签名等不稳定字段
            content_to_hash = {
                k: v
                for k, v in start_content.items()
                if k not in ("signatures", "unsigned")
            }

            canonical_start = json.dumps(
                content_to_hash,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            # commitment = base64(SHA256(公钥 + canonical_json))

            combined = their_key.encode("utf-8") + canonical_start.encode("utf-8")
            computed = base64.b64encode(hashlib.sha256(combined).digest()).decode(
                "utf-8"
            )

            if computed != their_commitment:
                logger.warning(
                    "[E2EE-Verify] Commitment 验证失败！"
                    f"expected={(their_commitment if isinstance(their_commitment, str) else '')[:16]}... "
                    f"computed={(computed or '')[:16]}..."
                )
                # 根据规范，commitment 不匹配应该取消验证
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
                    fetched_master_key_id, fetched_master_key = next(iter(master_keys.items()))
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
            logger.warning(
                "[E2EE-Verify] 忽略 done：会话已取消或 MAC 尚未验证通过"
            )
            return

        target_device = session.get("from_device") or session.get("their_device")
        if session.get("qr_scanned_by_us") and target_device and not session.get("done_sent"):
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

    # ========== 发送验证消息 ==========

import asyncio
import json

from astrbot.api import logger

from ..constants import (
    M_KEY_VERIFICATION_ACCEPT,
    M_KEY_VERIFICATION_CANCEL,
    M_KEY_VERIFICATION_DONE,
    M_KEY_VERIFICATION_KEY,
    M_KEY_VERIFICATION_MAC,
    M_KEY_VERIFICATION_READY,
    M_KEY_VERIFICATION_REQUEST,
    M_KEY_VERIFICATION_START,
    PREFIX_ED25519,
)
from .verification_constants import (
    VODOZEMAC_SAS_AVAILABLE,
    Sas,
)


class SASVerificationEventMixin:
    async def handle_verification_event(
        self, event_type: str, sender: str, content: dict
    ) -> bool:
        """处理验证事件"""
        transaction_id = content.get("transaction_id")

        if not transaction_id:
            logger.warning("[E2EE-Verify] 缺少 transaction_id，忽略事件")
            return False

        logger.info(
            f"[E2EE-Verify] 收到验证事件：{event_type} "
            f"from={sender} txn={transaction_id}"
        )
        logger.debug(
            f"[E2EE-Verify] 事件内容：{json.dumps(content, ensure_ascii=False)}"
        )

        handlers = {
            M_KEY_VERIFICATION_REQUEST: self._handle_request,
            M_KEY_VERIFICATION_READY: self._handle_ready,
            M_KEY_VERIFICATION_START: self._handle_start,
            M_KEY_VERIFICATION_ACCEPT: self._handle_accept,
            M_KEY_VERIFICATION_KEY: self._handle_key,
            M_KEY_VERIFICATION_MAC: self._handle_mac,
            M_KEY_VERIFICATION_DONE: self._handle_done,
            M_KEY_VERIFICATION_CANCEL: self._handle_cancel,
        }

        handler = handlers.get(event_type)
        if handler:
            await handler(sender, content, transaction_id)
            return True
        return False

    async def handle_in_room_verification_event(
        self, event_type: str, sender: str, content: dict, room_id: str, event_id: str
    ) -> bool:
        """处理房间内验证事件"""
        # In-room verification uses m.relates_to to link events
        relates_to = content.get("m.relates_to", {})
        msgtype = content.get("msgtype", "")

        # Debug: log the content structure
        logger.debug(
            f"[E2EE-Verify] 房间内事件内容：type={event_type}, "
            f"relates_to={relates_to}, msgtype={msgtype}"
        )

        # For m.key.verification.request events (either as event_type OR msgtype),
        # use event_id as transaction_id
        is_verification_request = (
            event_type == M_KEY_VERIFICATION_REQUEST
            or msgtype == "m.key.verification.request"
        )

        if is_verification_request:
            transaction_id = event_id
        else:
            # For other events, get transaction_id from m.relates_to
            # Matrix spec: in-room verification events use m.reference relationship
            transaction_id = relates_to.get("event_id") or content.get("transaction_id")

            # 如果 relates_to 中没有 event_id，尝试查找已有的验证会话
            if not transaction_id:
                # 尝试根据发送者和房间查找活跃的验证会话
                # 可能是：1. sender 是会话发起者 2. sender 是我们发起验证的目标设备的用户
                for txn_id, session in self._sessions.items():
                    if session.get("state") in ("done", "cancelled"):
                        continue
                    session_room = session.get("room_id")
                    session_sender = session.get("sender")
                    # 匹配条件：同一房间，且 sender 与会话相关（是发起者或是我们作为发起者时的目标）
                    if session_room == room_id and (
                        session_sender == sender  # sender 是会话发起者
                        or sender == self.user_id  # 或者是我们自己的其他设备发送的
                    ):
                        transaction_id = txn_id
                        logger.debug(
                            f"[E2EE-Verify] 从活跃会话推断 transaction_id: {txn_id[:16]}..."
                        )
                        break

        if not transaction_id:
            logger.warning(
                f"[E2EE-Verify] 房间内验证事件缺少 transaction_id: "
                f"type={event_type}, sender={sender}"
            )
            return False

        logger.debug(
            f"[E2EE-Verify] 收到房间内验证事件：{event_type} "
            f"from={sender} room={room_id[:16]}... txn={transaction_id[:16]}..."
        )

        # Store room_id in session for in-room responses
        if transaction_id not in self._sessions:
            self._sessions[transaction_id] = {}
        self._sessions[transaction_id]["room_id"] = room_id
        self._sessions[transaction_id]["is_in_room"] = True

        # CRITICAL: Check if this session was already taken over by another device
        # If so, ignore ALL subsequent events for this transaction (except cancel)
        session_state = self._sessions[transaction_id].get("state")
        if session_state == "handled_by_other_device":
            if event_type != M_KEY_VERIFICATION_CANCEL:
                logger.debug(
                    f"[E2EE-Verify] 会话已由其他设备处理，忽略事件：{event_type}"
                )
                return True  # Ignore this event

        # Check if this event is from our own user
        if sender == self.user_id:
            from_device = content.get("from_device")

            # Skip our own key/mac/done/accept events (these are echoes of what we sent)
            # We only need to process these events from the OTHER party
            if event_type in (
                M_KEY_VERIFICATION_KEY,
                M_KEY_VERIFICATION_MAC,
                M_KEY_VERIFICATION_DONE,
                M_KEY_VERIFICATION_ACCEPT,
            ):
                logger.debug(f"[E2EE-Verify] 跳过自己发送的事件：{event_type}")
                return True  # Ignore our own echoed events

            if from_device and from_device != self.device_id:
                # 只有当事件明确表明另一个设备正在进行交互时（例如 ready/start/accept），我们才退出
                # 忽略 request 事件（因为那是发起请求，不代表接管）
                if event_type not in (
                    M_KEY_VERIFICATION_REQUEST,
                    M_KEY_VERIFICATION_CANCEL,
                ):
                    logger.info(
                        f"[E2EE-Verify] 检测到其他设备 {from_device} 正在处理验证 txn={transaction_id[:8]}...，本设备将静默退出"
                    )
                    # 标记会话为已由其他设备处理，停止本地处理
                    if transaction_id in self._sessions:
                        self._sessions[transaction_id]["state"] = (
                            "handled_by_other_device"
                        )
                    return True  # 已处理（忽略）

        handlers = {
            M_KEY_VERIFICATION_REQUEST: self._handle_in_room_request,
            M_KEY_VERIFICATION_READY: self._handle_ready,
            M_KEY_VERIFICATION_START: self._handle_start,
            M_KEY_VERIFICATION_ACCEPT: self._handle_accept,
            M_KEY_VERIFICATION_KEY: self._handle_key,
            M_KEY_VERIFICATION_MAC: self._handle_mac,
            M_KEY_VERIFICATION_DONE: self._handle_done,
            M_KEY_VERIFICATION_CANCEL: self._handle_cancel,
        }

        # For verification requests (m.room.message with msgtype m.key.verification.request),
        # use _handle_in_room_request directly
        if is_verification_request:
            await self._handle_in_room_request(sender, content, transaction_id)
            return True

        handler = handlers.get(event_type)
        if handler:
            await handler(sender, content, transaction_id)
            return True
        return False

    async def _handle_in_room_request(
        self, sender: str, content: dict, transaction_id: str
    ):
        """处理房间内验证请求"""
        from_device = content.get("from_device")
        methods = content.get("methods", [])

        if not from_device:
            logger.warning("[E2EE-Verify] 房间内验证请求缺少 from_device")
            return

        logger.info(
            f"[E2EE-Verify] 收到房间内验证请求："
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

        session = self._sessions.get(transaction_id, {})
        session.update(
            {
                "sender": sender,
                "from_device": from_device,
                "methods": methods,
                "state": "requested",
                "sas": sas,
            }
        )
        self._sessions[transaction_id] = session

        # TOFU: Check if device is trusted
        fingerprint = None
        try:
            # Query device keys to get the real fingerprint (Ed25519 key)
            logger.debug(f"[E2EE-Verify] Querying keys for {sender}|{from_device}")
            resp = await self.client.query_keys({sender: []})
            devices = resp.get("device_keys", {}).get(sender, {})
            device_info = devices.get(from_device, {})
            keys = device_info.get("keys", {})
            # Key format: "ed25519:<device_id>"
            fingerprint = keys.get(f"{PREFIX_ED25519}{from_device}")
        except Exception as e:
            logger.warning(
                f"[E2EE-Verify] Failed to query keys for {sender}|{from_device}: {e}"
            )

        if fingerprint:
            session["fingerprint"] = fingerprint
            if self.device_store.is_trusted(sender, from_device, fingerprint):
                logger.info(f"[E2EE-Verify] Trusted device {sender}|{from_device}")
            else:
                logger.info(
                    f"[E2EE-Verify] Untrusted device {sender}|{from_device} (fingerprint: {fingerprint[:8]}...)"
                )

                # Notify user
                await self._notify_user_for_approval(
                    sender, from_device, session.get("room_id")
                )

                if self.auto_verify_mode == "auto_accept":
                    if self.trust_on_first_use:
                        logger.info(
                            "[E2EE-Verify] TOFU enabled: proceeding with auto-accept"
                        )
                    else:
                        logger.info(
                            "[E2EE-Verify] TOFU disabled: auto-accept disabled for untrusted device"
                        )
                        return
        else:
            logger.warning(
                f"[E2EE-Verify] Could not find Ed25519 key for {sender}|{from_device}"
            )
            # If we can't find the key, we can't verify it properly.
            # But if TOFU is enabled, maybe we should proceed?
            # No, without a key we can't verify signatures anyway.
            # But the verification process itself exchanges keys.
            # Let's proceed but warn.
            if self.auto_verify_mode == "auto_accept" and not self.trust_on_first_use:
                logger.info(
                    "[E2EE-Verify] Key not found and TOFU disabled: aborting auto-accept"
                )
                return

        if self.auto_verify_mode == "auto_reject":
            logger.info("[E2EE-Verify] 自动拒绝验证请求 (mode=auto_reject)")
            await self._send_in_room_cancel(
                session["room_id"], transaction_id, "m.user", "自动拒绝"
            )
            return

        if self.auto_verify_mode == "manual":
            logger.info("[E2EE-Verify] 手动模式，记录验证请求但不响应 (mode=manual)")
            return

        # auto_accept: 发送 ready
        if "m.sas.v1" in methods:
            logger.info("[E2EE-Verify] 自动接受房间内验证请求 (mode=auto_accept)")
            # 触发一次自身设备密钥查询，帮助服务器同步我们的设备信息
            # 这有助于确保对方客户端能获取到我们的设备密钥
            try:
                await self.client.query_keys({self.user_id: []})
                logger.debug("[E2EE-Verify] 已触发自身设备密钥查询")
            except Exception as e:
                logger.debug(f"[E2EE-Verify] 自身密钥查询失败（非关键）：{e}")

            # 等待一小段时间，让设备密钥有时间在服务器间传播
            # 这有助于避免 "unknown_device" 错误
            await asyncio.sleep(1.0)
            await self._send_in_room_ready(session["room_id"], transaction_id)
        else:
            logger.warning(f"[E2EE-Verify] 不支持的验证方法：{methods}")
            await self._send_in_room_cancel(
                session["room_id"],
                transaction_id,
                "m.unknown_method",
                "不支持的验证方法",
            )

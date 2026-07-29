import secrets
import time

from astrbot.api import logger

from ..constants import (
    M_FORWARDED_ROOM_KEY,
    M_ROOM_ENCRYPTED,
    M_ROOM_KEY_REQUEST,
    M_ROOM_KEY_WITHHELD,
    MEGOLM_ALGO,
    PREFIX_CURVE25519,
    PREFIX_ED25519,
    SIGNED_CURVE25519,
)
from .constants import (
    DEFAULT_OLM_RECOVERY_RETRY_SEC,
    M_DUMMY,
    VALID_TO_DEVICE_WITHHELD_CODES,
    VALID_WITHHELD_CODES,
    WITHHELD_NO_OLM,
    WITHHELD_UNAUTHORISED,
    WITHHELD_UNAVAILABLE,
    WITHHELD_UNVERIFIED,
)


class E2EEManagerRequestsMixin:
    async def _request_new_session(
        self, sender_key: str, sender_user_id: str | None = None
    ) -> bool:
        """
        当检测到未知一次性密钥时，主动建立新的 Olm 会话

        通过 claim 对方的一次性密钥，创建新的出站 Olm 会话，
        然后发送加密的 m.dummy 消息，通知对方使用新会话通信。

        Args:
            sender_key: 发送者的 curve25519 密钥
            sender_user_id: 可选的发送者用户 ID（如果已知，可用于查询设备）
        """
        masked_sender_key = (sender_key or "")[:8]
        if not self._olm or not sender_user_id or not sender_key:
            logger.warning(
                f"Cannot recover Olm session: sender={sender_user_id or '<empty>'} "
                f"key={masked_sender_key}..."
            )
            return False

        result = await self._find_device_by_sender_key(sender_key, sender_user_id)
        if not result:
            # Never pick an arbitrary device. It would not repair the session
            # associated with the sender Curve25519 identity key.
            logger.warning(
                f"No signed device matches sender_key {masked_sender_key}..."
            )
            return False
        target_user, target_device = result

        attempts = getattr(self, "_olm_recovery_attempts", None)
        if not isinstance(attempts, dict):
            attempts = {}
            self._olm_recovery_attempts = attempts
        attempt_key = (target_user, target_device)
        now = time.monotonic()
        retry_interval = float(
            getattr(
                self,
                "_olm_recovery_retry_interval_sec",
                DEFAULT_OLM_RECOVERY_RETRY_SEC,
            )
        )
        last_attempt = attempts.get(attempt_key)
        if last_attempt is not None and now - float(last_attempt) < retry_interval:
            return False
        attempts[attempt_key] = now

        try:
            device_info = await self._get_validated_device_info(
                target_user,
                target_device,
                force_query=True,
            )
            if not device_info:
                return False
            keys = device_info.get("keys", {})
            their_curve_key = keys.get(f"{PREFIX_CURVE25519}{target_device}")
            their_ed25519_key = keys.get(f"{PREFIX_ED25519}{target_device}")
            if their_curve_key != sender_key or not their_ed25519_key:
                logger.warning("Olm recovery device identity changed during lookup")
                return False

            claim_resp = await self.client.claim_keys(
                {target_user: {target_device: SIGNED_CURVE25519}}
            )
            device_otks = (
                (claim_resp.get("one_time_keys") or {}).get(target_user) or {}
            ).get(target_device) or {}
            selected = self._olm.select_verified_one_time_key(
                target_user,
                target_device,
                their_ed25519_key,
                device_otks,
            )
            if not selected:
                logger.warning(
                    f"No valid signed one-time key for {target_user}/{target_device}"
                )
                return False
            _, their_one_time_key = selected
            session = self._olm.create_outbound_session(
                their_curve_key,
                their_one_time_key,
            )
            encrypted = self._olm.encrypt_olm(
                their_curve_key,
                {},
                session=session,
                recipient_user_id=target_user,
                recipient_ed25519_key=their_ed25519_key,
                event_type=M_DUMMY,
            )
            await self.client.send_to_device(
                M_ROOM_ENCRYPTED,
                {target_user: {target_device: encrypted}},
                secrets.token_hex(16),
            )
            self._mark_olm_send_succeeded(target_user, target_device)
            logger.info(
                f"Sent encrypted m.dummy and established a new Olm session "
                f"with {target_user}/{target_device}"
            )
            return True
        except Exception as e:
            logger.warning(f"Failed to establish a new Olm session: {e}")
            return False

    async def _request_room_key(
        self,
        room_id: str,
        session_id: str,
        sender_key: str | None,
        sender: str | None = None,
    ) -> bool:
        """
        发送 m.room_key_request 请求密钥

        Args:
            room_id: 房间 ID
            session_id: 会话 ID
            sender_key: 发送者的 curve25519 密钥

        Returns:
            Whether a request was sent. Throttled duplicate requests return False.
        """
        if not room_id or not session_id:
            logger.warning("Skipping room-key request without room_id or session_id")
            return False

        request_key = (room_id, session_id)
        now = time.monotonic()
        # Matrix key requests are restricted to verified devices of our own
        # user. The deprecated sender fields are not an authorization source.
        recipients = {self.user_id}
        if sender and sender != self.user_id:
            recipients.add(sender)

        async with self._room_key_request_lock:
            expiry = self._room_key_request_expiry_sec
            for pending_key, pending in list(self._pending_room_key_requests.items()):
                if now - float(pending.get("created_at", now)) >= expiry:
                    self._pending_room_key_requests.pop(pending_key, None)

            pending = self._pending_room_key_requests.get(request_key)
            if pending:
                pending_recipients = pending.get("recipients")
                if isinstance(pending_recipients, set):
                    recipients.update(pending_recipients)
                if (
                    now - float(pending.get("last_sent_at", 0.0))
                    < self._room_key_request_retry_interval_sec
                ):
                    return False
                request_id = str(pending["request_id"])
                created_at = float(pending.get("created_at", now))
            else:
                request_id = secrets.token_hex(16)
                created_at = now

            self._pending_room_key_requests[request_key] = {
                "request_id": request_id,
                "recipients": recipients,
                "created_at": created_at,
                "last_sent_at": now,
            }

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
        messages = {user_id: {"*": content} for user_id in sorted(recipients)}

        try:
            await self.client.send_to_device(
                M_ROOM_KEY_REQUEST,
                messages,
                secrets.token_hex(16),
            )
            logger.info(
                f"Sent room-key request: room={room_id[:16]}... "
                f"session={session_id[:8]}... recipients={len(recipients)}"
            )
            return True
        except Exception as e:
            async with self._room_key_request_lock:
                current = self._pending_room_key_requests.get(request_key)
                if current and current.get("request_id") == request_id:
                    current["last_sent_at"] = 0.0
            logger.warning(f"Failed to send room-key request: {e}")
            return False

    async def _cancel_room_key_request(self, room_id: str, session_id: str) -> bool:
        """Cancel a pending room-key request after the session is received.

        Args:
            room_id: Room containing the Megolm session.
            session_id: Megolm session identifier.

        Returns:
            Whether a cancellation was sent successfully.
        """
        request_key = (room_id, session_id)
        async with self._room_key_request_lock:
            pending = self._pending_room_key_requests.get(request_key)
        if not pending:
            return False

        recipients = pending.get("recipients")
        if not isinstance(recipients, set) or not recipients:
            return False
        content = {
            "action": "request_cancellation",
            "request_id": str(pending["request_id"]),
            "requesting_device_id": self.device_id,
        }
        try:
            await self.client.send_to_device(
                M_ROOM_KEY_REQUEST,
                {user_id: {"*": content} for user_id in sorted(recipients)},
                secrets.token_hex(16),
            )
            async with self._room_key_request_lock:
                current = self._pending_room_key_requests.get(request_key)
                if current and current.get("request_id") == pending.get("request_id"):
                    self._pending_room_key_requests.pop(request_key, None)
            logger.debug(f"Cancelled room-key request: session={session_id[:8]}...")
            return True
        except Exception as e:
            logger.debug(f"Failed to cancel room-key request: {e}")
            return False

    async def _send_room_key_withheld(
        self,
        sender: str,
        requesting_device_id: str,
        room_id: str | None,
        session_id: str | None,
        code: str,
        reason: str,
    ) -> bool:
        """Tell a requesting device why a Megolm session cannot be shared.

        Args:
            sender: Requesting user ID.
            requesting_device_id: Requesting device ID.
            room_id: Room containing the requested session.
            session_id: Requested Megolm session ID.
            code: Matrix room-key withholding code.
            reason: Human-readable withholding reason.

        Returns:
            Whether the withholding event was sent successfully.
        """
        if (
            not all(
                isinstance(value, str) and value
                for value in (sender, requesting_device_id)
            )
            or code not in VALID_TO_DEVICE_WITHHELD_CODES
            or not isinstance(reason, str)
            or not reason
        ):
            return False
        if code != WITHHELD_NO_OLM and not all(
            isinstance(value, str) and value for value in (room_id, session_id)
        ):
            return False
        if not self._olm:
            return False
        content = {
            "algorithm": MEGOLM_ALGO,
            # This is the sender of the withheld event, not the device which
            # originally created the requested Megolm session.
            "sender_key": str(self._olm.curve25519_key),
            "code": code,
            "reason": reason,
        }
        if code != WITHHELD_NO_OLM:
            content["room_id"] = room_id
            content["session_id"] = session_id
        try:
            await self.client.send_to_device(
                M_ROOM_KEY_WITHHELD,
                {sender: {requesting_device_id: content}},
                secrets.token_hex(16),
            )
            return True
        except Exception as e:
            logger.debug(f"Failed to send room-key withheld event: {e}")
            return False

    def _mark_olm_send_succeeded(self, user_id: str, device_id: str) -> None:
        """Allow a future m.no_olm after a successful Olm communication."""
        sent = getattr(self, "_no_olm_withheld_sent", None)
        if isinstance(sent, set):
            sent.discard((user_id, device_id))

    async def _send_no_olm_withheld(self, user_id: str, device_id: str) -> bool:
        """Send the single mailbox-safe m.no_olm signal required by Matrix."""
        if not all(isinstance(value, str) and value for value in (user_id, device_id)):
            return False
        sent = getattr(self, "_no_olm_withheld_sent", None)
        if not isinstance(sent, set):
            sent = set()
            self._no_olm_withheld_sent = sent
        peer = (user_id, device_id)
        if peer in sent:
            return False
        if await self._send_room_key_withheld(
            user_id,
            device_id,
            None,
            None,
            WITHHELD_NO_OLM,
            "An Olm session could not be established",
        ):
            sent.add(peer)
            return True
        return False

    async def handle_room_key_withheld(self, sender: str, content: dict) -> bool:
        """Record an incoming withheld notice and recover from m.no_olm."""
        if not isinstance(content, dict) or content.get("algorithm") != MEGOLM_ALGO:
            return False
        code = content.get("code")
        sender_key = content.get("sender_key")
        reason = content.get("reason")
        if (
            code not in VALID_WITHHELD_CODES
            or not isinstance(sender_key, str)
            or not sender_key
            or (reason is not None and not isinstance(reason, str))
        ):
            return False
        room_id = content.get("room_id")
        session_id = content.get("session_id")
        if code == WITHHELD_NO_OLM:
            if room_id is not None or session_id is not None:
                return False
        elif not all(
            isinstance(value, str) and value for value in (room_id, session_id)
        ):
            return False

        records = getattr(self, "_room_key_withheld", None)
        if not isinstance(records, dict):
            records = {}
            self._room_key_withheld = records
        records[(sender, str(room_id or ""), str(session_id or ""))] = dict(content)
        if code == WITHHELD_NO_OLM:
            return await self._request_new_session(sender_key, sender)
        return True

    async def _is_own_device_trusted(
        self,
        device_id: str,
        device_info: dict,
        key_query_response: dict | None = None,
    ) -> bool:
        """Verify an own-user device via SAS, cross-signing, or configured TOFU."""
        if (
            not self._olm
            or not isinstance(device_id, str)
            or not device_id
            or not self._olm.verify_device_keys(
                self.user_id,
                device_id,
                device_info,
            )
        ):
            return False
        ed25519_key = (device_info.get("keys") or {}).get(
            f"{PREFIX_ED25519}{device_id}"
        )
        if not isinstance(ed25519_key, str) or not ed25519_key:
            return False

        verification = getattr(self, "_verification", None)
        if verification:
            device_store = getattr(verification, "device_store", None)
            if device_store and device_store.is_trusted(
                self.user_id,
                device_id,
                ed25519_key,
            ):
                return True

        cross_signing = getattr(self, "_cross_signing", None)
        if (
            cross_signing
            and cross_signing.self_signing_key
            and cross_signing.master_key
        ):
            response = key_query_response
            if not isinstance(response, dict):
                try:
                    response = await self.client.query_keys({self.user_id: []})
                except Exception as e:
                    logger.warning(f"Unable to query cross-signing keys: {e}")
                    response = {}
            master_key = str(cross_signing.master_key)
            self_signing_key = str(cross_signing.self_signing_key)
            master_info = (response.get("master_keys") or {}).get(self.user_id)
            self_signing_info = (response.get("self_signing_keys") or {}).get(
                self.user_id
            )
            if (
                isinstance(master_info, dict)
                and (master_info.get("keys") or {}).get(f"ed25519:{master_key}")
                == master_key
                and isinstance(self_signing_info, dict)
                and (self_signing_info.get("keys") or {}).get(
                    f"ed25519:{self_signing_key}"
                )
                == self_signing_key
                and self._olm.verify_json_signature(
                    self_signing_info,
                    self.user_id,
                    f"ed25519:{master_key}",
                    master_key,
                )
                and self._olm.verify_json_signature(
                    device_info,
                    self.user_id,
                    f"ed25519:{self_signing_key}",
                    self_signing_key,
                )
            ):
                return True

        return bool(getattr(self, "trust_on_first_use", False))

    async def respond_to_key_request(
        self,
        sender: str,
        requesting_device_id: str,
        room_id: str,
        session_id: str,
    ) -> bool:
        """
        响应来自其他设备的密钥请求

        只有同一用户的已验证设备才会收到响应。

        Args:
            sender: 请求者用户 ID
            requesting_device_id: 请求者设备 ID
            room_id: 房间 ID
            session_id: 会话 ID

        Returns:
            Whether the requested session was forwarded successfully.
        """
        if not self._olm or not self._initialized:
            logger.warning("未初始化，无法响应密钥请求")
            return False
        if not all(
            isinstance(value, str) and value
            for value in (sender, requesting_device_id, room_id, session_id)
        ):
            return False

        try:
            # 只响应同一用户的请求（安全限制）
            if sender != self.user_id:
                logger.debug(f"忽略来自其他用户的密钥请求：{sender}")
                await self._send_room_key_withheld(
                    sender,
                    requesting_device_id,
                    room_id,
                    session_id,
                    WITHHELD_UNAUTHORISED,
                    "Room keys are only shared with this account's devices",
                )
                return False

            # 不响应自己设备的请求
            if requesting_device_id == self.device_id:
                logger.debug("忽略来自自己的密钥请求")
                return False

            # 获取请求者的设备密钥信息
            resp = await self.client.query_keys({sender: []})
            devices = (resp.get("device_keys") or {}).get(sender) or {}
            device_info = devices.get(requesting_device_id, {})
            curve_key = device_info.get("keys", {}).get(
                f"{PREFIX_CURVE25519}{requesting_device_id}"
            )
            ed25519_key = device_info.get("keys", {}).get(
                f"{PREFIX_ED25519}{requesting_device_id}"
            )

            if (
                not curve_key
                or not ed25519_key
                or not self._olm.verify_device_keys(
                    sender,
                    requesting_device_id,
                    device_info,
                )
            ):
                logger.warning(
                    f"Missing or invalid signed identity keys for requesting device "
                    f"{sender}/{requesting_device_id}"
                )
                await self._send_room_key_withheld(
                    sender,
                    requesting_device_id,
                    room_id,
                    session_id,
                    WITHHELD_UNAVAILABLE,
                    "The requesting device keys are unavailable",
                )
                return False

            if self._store:
                self._store.save_device_keys(sender, requesting_device_id, device_info)

            if not await self._is_own_device_trusted(
                requesting_device_id,
                device_info,
                resp,
            ):
                logger.warning(
                    f"拒绝向未验证的设备 {requesting_device_id} 转发密钥 "
                    f"(session={(session_id or '')[:8]}...)"
                )
                await self._send_room_key_withheld(
                    sender,
                    requesting_device_id,
                    room_id,
                    session_id,
                    WITHHELD_UNVERIFIED,
                    "The requesting device is not verified",
                )
                return False

            # 获取请求的 Megolm 会话
            session = self._olm.get_megolm_inbound_session(session_id)
            if not session:
                logger.debug(f"没有请求的会话：session={(session_id or '')[:8]}...")
                await self._send_room_key_withheld(
                    sender,
                    requesting_device_id,
                    room_id,
                    session_id,
                    WITHHELD_UNAVAILABLE,
                    "The requested room key is not available on this device",
                )
                return False

            # 导出会话密钥
            try:
                first_index = self._olm.get_megolm_first_known_index(session)
                exported_key = session.export_at(first_index)
                logger.info(
                    f"导出会话密钥：session={(session_id or '')[:8]}..., "
                    f"first_index={first_index}"
                )
            except Exception as e:
                logger.warning(f"导出会话密钥失败：{e}")
                await self._send_room_key_withheld(
                    sender,
                    requesting_device_id,
                    room_id,
                    session_id,
                    WITHHELD_UNAVAILABLE,
                    "The requested room key could not be exported",
                )
                return False

            metadata = None
            get_metadata = getattr(
                self._store,
                "get_megolm_inbound_metadata",
                None,
            )
            if callable(get_metadata):
                metadata = get_metadata(session_id)
            if not isinstance(metadata, dict) or metadata.get("room_id") != room_id:
                logger.warning(
                    "Refusing room-key forwarding without matching authenticated "
                    "session metadata"
                )
                await self._send_room_key_withheld(
                    sender,
                    requesting_device_id,
                    room_id,
                    session_id,
                    WITHHELD_UNAVAILABLE,
                    "The requested room key has no validated provenance metadata",
                )
                return False

            # RequestedKeyInfo.sender_key is deprecated and MUST NOT be used to
            # locate or establish provenance for a session.
            original_sender_key = metadata.get("sender_key")
            if not isinstance(original_sender_key, str) or not original_sender_key:
                await self._send_room_key_withheld(
                    sender,
                    requesting_device_id,
                    room_id,
                    session_id,
                    WITHHELD_UNAVAILABLE,
                    "The requested room key has incomplete provenance metadata",
                )
                return False
            claimed_keys = metadata.get("sender_claimed_keys")
            if not isinstance(claimed_keys, dict):
                claimed_keys = {}
            original_ed25519 = claimed_keys.get("ed25519")
            if not isinstance(original_ed25519, str) or not original_ed25519:
                await self._send_room_key_withheld(
                    sender,
                    requesting_device_id,
                    room_id,
                    session_id,
                    WITHHELD_UNAVAILABLE,
                    "The requested room key has incomplete claimed-key metadata",
                )
                return False

            forwarding_chain = metadata.get("forwarding_curve25519_key_chain")
            if not isinstance(forwarding_chain, list):
                forwarding_chain = []
            forwarding_chain = [key for key in forwarding_chain if isinstance(key, str)]

            # 构造 m.forwarded_room_key 内容
            # 根据 Matrix 规范，type 不应包含在内容中（它是事件类型）
            forwarded_room_key = {
                "algorithm": MEGOLM_ALGO,
                "room_id": room_id,
                "sender_key": original_sender_key,
                "session_id": session_id,
                "session_key": exported_key.to_base64(),
                "sender_claimed_ed25519_key": original_ed25519,
                "forwarding_curve25519_key_chain": forwarding_chain,
            }
            withheld = metadata.get("withheld")
            if (
                isinstance(withheld, dict)
                and isinstance(withheld.get("code"), str)
                and isinstance(withheld.get("reason"), str)
            ):
                forwarded_room_key["withheld"] = {
                    "code": withheld["code"],
                    "reason": withheld["reason"],
                }

            # Establish an Olm session on demand and bind the wrapper to the
            # requesting device's Ed25519 key before forwarding the session.
            encrypted_content = await self._encrypt_to_device(
                target_user=sender,
                target_device=requesting_device_id,
                event_type=M_FORWARDED_ROOM_KEY,
                content=forwarded_room_key,
            )

            if not encrypted_content:
                await self._send_no_olm_withheld(sender, requesting_device_id)
                return False

            txn_id = secrets.token_hex(16)
            await self.client.send_to_device(
                M_ROOM_ENCRYPTED,
                {sender: {requesting_device_id: encrypted_content}},
                txn_id,
            )
            self._mark_olm_send_succeeded(sender, requesting_device_id)

            logger.info(
                f"已加密转发密钥：session={(session_id or '')[:8]}... -> device={requesting_device_id}"
            )
            return True

        except Exception as e:
            logger.warning(f"响应密钥请求失败：{e}")
            await self._send_room_key_withheld(
                sender,
                requesting_device_id,
                room_id,
                session_id,
                WITHHELD_UNAVAILABLE,
                "The room-key request could not be processed",
            )
            return False

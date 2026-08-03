import secrets

from astrbot.api import logger

from ....constants import (
    M_FORWARDED_ROOM_KEY,
    M_ROOM_ENCRYPTED,
    MEGOLM_ALGO,
    PREFIX_CURVE25519,
    PREFIX_ED25519,
)
from ...constants import (
    WITHHELD_UNAUTHORISED,
    WITHHELD_UNAVAILABLE,
    WITHHELD_UNVERIFIED,
)


class E2EEManagerRequestsRespondOperationsMixin:
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
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
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

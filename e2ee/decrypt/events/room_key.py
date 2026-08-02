from astrbot.api import logger

from ....constants import MEGOLM_ALGO
from ...constants import (
    VALID_WITHHELD_CODES,
    WITHHELD_NO_OLM,
)


class E2EEManagerDecryptRoomKeyMixin:
    async def handle_room_key(
        self,
        event: dict,
        sender_key: str,
        *,
        sender_claimed_keys: dict[str, str] | None = None,
        sender_user_id: str | None = None,
        forwarded: bool = False,
    ):
        """
        处理 m.room_key 事件 (接收 Megolm 会话密钥)

        Args:
            event: 解密后的 m.room_key 事件内容
            sender_key: 发送者的 curve25519 密钥
            sender_claimed_keys: Olm 载荷中发送设备声明的签名密钥
            sender_user_id: Sender user ID authenticated by the Olm plaintext
            forwarded: Whether the decrypted event was m.forwarded_room_key.
        """
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
            return

        if not isinstance(event, dict):
            return

        room_id = event.get("room_id")
        session_id = event.get("session_id")
        session_key = event.get("session_key")
        algorithm = event.get("algorithm")

        if algorithm != MEGOLM_ALGO:
            logger.warning(f"不支持的密钥算法：{algorithm}")
            return

        if not all(
            isinstance(value, str) and value
            for value in (room_id, session_id, session_key, sender_key)
        ):
            logger.warning("m.room_key 事件缺少必要字段")
            return

        withheld = None
        if forwarded:
            forwarded_chain = event.get("forwarding_curve25519_key_chain")
            original_sender_key = event.get("sender_key")
            forwarded_ed25519 = event.get("sender_claimed_ed25519_key")
            if (
                sender_user_id != self.user_id
                or not isinstance(forwarded_chain, list)
                or not all(isinstance(key, str) and key for key in forwarded_chain)
                or not isinstance(original_sender_key, str)
                or not original_sender_key
                or not isinstance(forwarded_ed25519, str)
                or not forwarded_ed25519
            ):
                logger.warning("Rejected malformed or cross-user forwarded room key")
                return

            source = await self._find_device_by_sender_key(
                sender_key,
                sender_user_id,
            )
            if not source or source[0] != self.user_id:
                logger.warning("Rejected forwarded room key from an unknown device")
                return
            source_device = source[1]
            device_info = await self._get_validated_device_info(
                self.user_id,
                source_device,
            )
            if not device_info or not await self._is_own_device_trusted(
                source_device,
                device_info,
            ):
                logger.warning("Rejected forwarded room key from an unverified device")
                return

            raw_withheld = event.get("withheld")
            if raw_withheld is not None:
                if (
                    not isinstance(raw_withheld, dict)
                    or raw_withheld.get("code") not in VALID_WITHHELD_CODES
                    or raw_withheld.get("code") == WITHHELD_NO_OLM
                    or not isinstance(raw_withheld.get("reason"), str)
                ):
                    logger.warning("Rejected malformed forwarded-key withheld data")
                    return
                withheld = {
                    "code": raw_withheld["code"],
                    "reason": raw_withheld["reason"],
                }
        else:
            if not isinstance(sender_user_id, str) or not sender_user_id:
                logger.warning("Rejected room key without an authenticated sender")
                return
            forwarded_chain = []
            original_sender_key = sender_key
            forwarded_ed25519 = None

        claimed_keys = sender_claimed_keys
        if isinstance(forwarded_ed25519, str) and forwarded_ed25519:
            claimed_keys = {"ed25519": forwarded_ed25519}
        if not isinstance(claimed_keys, dict):
            claimed_keys = {}
        else:
            claimed_keys = {
                str(algorithm): key
                for algorithm, key in claimed_keys.items()
                if isinstance(key, str)
            }
        if not isinstance(claimed_keys.get("ed25519"), str) or not claimed_keys.get(
            "ed25519"
        ):
            logger.warning("Rejected room key without an authenticated Ed25519 key")
            return

        # Only a direct m.room_key can declare shareability. A forwarded key
        # lacks this authenticated assertion and is therefore conservative.
        shared_history = not forwarded and event.get("shared_history") is True
        stored_forwarding_chain = list(forwarded_chain)
        if (
            forwarded
            and isinstance(sender_key, str)
            and sender_key
            and (
                not stored_forwarding_chain or stored_forwarding_chain[-1] != sender_key
            )
        ):
            # The content omits its current Olm sender. Persist that device as
            # the newest hop so a subsequent forward retains full provenance.
            stored_forwarding_chain.append(sender_key)

        imported = self._olm.add_megolm_inbound_session(
            room_id,
            session_id,
            session_key,
            original_sender_key,
            claimed_keys,
            stored_forwarding_chain,
            shared_history,
            None if forwarded else sender_user_id,
            withheld if forwarded else {},
        )
        if imported is False:
            logger.warning(
                f"Failed to import the Megolm key for room {room_id}; "
                "keeping the room-key request pending"
            )
            return
        logger.info(f"收到房间 {room_id} 的 Megolm 密钥")

        # Matrix requires the requester to cancel the outstanding request once
        # any device supplies the session. This also prevents repeated replies.
        await self._cancel_room_key_request(room_id, session_id)

        # 自动备份新接收到的密钥
        if self._key_backup and self.enable_key_backup:
            try:
                await self._key_backup.upload_single_key(
                    room_id=room_id,
                    session_id=session_id,
                    session_key=session_key,
                    sender_key=original_sender_key,
                    sender_claimed_keys=claimed_keys,
                    forwarding_curve25519_key_chain=stored_forwarding_chain,
                    shared_history=shared_history,
                )
            except Exception as e:
                logger.warning(f"自动备份密钥失败：{e}")

"""Forwarding an exported Megolm session to a requesting device."""

import secrets

from astrbot.api import logger

from .....constants import (
    M_FORWARDED_ROOM_KEY,
    M_ROOM_ENCRYPTED,
    MEGOLM_ALGO,
)


class E2EEManagerRequestsRespondForwardMixin:
    """Encrypt and send an m.forwarded_room_key to the requesting device."""

    async def _forward_session(
        self,
        sender: str,
        requesting_device_id: str,
        room_id: str,
        session_id: str,
        exported_key,
        original_sender_key: str,
        original_ed25519: str,
        forwarding_chain: list,
        metadata: dict,
    ) -> bool:
        """Encrypt and send the forwarded room key; return send success."""
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

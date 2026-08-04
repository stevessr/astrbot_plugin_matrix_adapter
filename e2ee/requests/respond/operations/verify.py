"""Requester verification for room-key requests."""

from astrbot.api import logger

from .....constants import PREFIX_CURVE25519, PREFIX_ED25519
from ....constants import (
    WITHHELD_UNAUTHORISED,
    WITHHELD_UNAVAILABLE,
    WITHHELD_UNVERIFIED,
)


class E2EEManagerRequestsRespondVerifyMixin:
    """Verify a requesting device and load its identity keys."""

    async def _verify_requester(
        self,
        sender: str,
        requesting_device_id: str,
        room_id: str,
        session_id: str,
    ):
        """Verify the requesting device and return (device_info, query response).

        Sends a withholding notice and returns None when the requester must
        be refused.
        """
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
            return None

        # 不响应自己设备的请求
        if requesting_device_id == self.device_id:
            logger.debug("忽略来自自己的密钥请求")
            return None

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
            return None

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
            return None

        return device_info, resp

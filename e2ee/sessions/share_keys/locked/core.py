"""Locked room-key distribution orchestration."""

from astrbot.api import logger

from .....constants import SIGNED_CURVE25519


class E2EEManagerSessionShareKeysLockedCoreMixin:
    """在会话锁内查询设备、建立 Olm 并发送房间密钥。"""

    async def _ensure_room_keys_sent_locked(
        self,
        *,
        room_id: str,
        members: list[str],
        session_id: str,
        session_key: str,
        reason: str,
        shared_history: bool | None,
    ) -> int:
        """Distribute one session while its per-session lock is held."""
        if not self._outbound_session_is_current(room_id, session_id):
            logger.debug(
                f"Skip stale room-key distribution: room={room_id} "
                f"session={session_id[:8]}..."
            )
            return 0

        shared_devices = self._room_key_share_cache.setdefault(session_id, set())
        if shared_history is None:
            metadata_getter = getattr(
                self._olm,
                "get_megolm_outbound_shared_history",
                None,
            )
            shared_history = (
                metadata_getter(room_id) if callable(metadata_getter) else None
            )
        # Unknown/legacy metadata must not be promoted to shareable.
        shared_history = shared_history is True

        try:
            devices_to_send = await self._collect_room_key_devices(
                room_id=room_id,
                members=members,
                shared_devices=shared_devices,
            )

            if not devices_to_send:
                logger.debug(
                    f"No devices eligible for room-key sharing: "
                    f"room={room_id} reason={reason} "
                    f"members={len(members)}"
                )
                return 0

            one_time_claim: dict[str, dict[str, str]] = {}
            for user_id, device_id, curve_key, _ in devices_to_send:
                if not self._olm.get_olm_session(curve_key):
                    one_time_claim.setdefault(user_id, {})[device_id] = (
                        SIGNED_CURVE25519
                    )

            one_time_keys = {}
            if one_time_claim:
                claimed = await self.client.claim_keys(one_time_claim)
                one_time_keys = claimed.get("one_time_keys", {})
                if not isinstance(one_time_keys, dict):
                    one_time_keys = {}

            sent_count = 0
            for user_id, device_id, curve_key, ed_key in devices_to_send:
                result = await self._send_room_key_to_device(
                    user_id,
                    device_id,
                    curve_key,
                    ed_key,
                    room_id=room_id,
                    session_id=session_id,
                    session_key=session_key,
                    shared_history=shared_history,
                    one_time_keys=one_time_keys,
                    shared_devices=shared_devices,
                )
                if result is None:
                    # Membership/device callbacks rotated this session while
                    # the network requests above were in flight.
                    break
                if result:
                    sent_count += 1

            logger.info(
                f"已向 {sent_count}/{len(devices_to_send)} 个设备分发房间 {room_id} 的密钥 "
                f"(reason={reason})"
            )
            return sent_count
        except Exception as e:
            logger.error(f"密钥分发失败：{e}")
            return 0

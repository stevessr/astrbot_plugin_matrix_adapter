"""Locked room-key device distribution implementation."""

import secrets

from astrbot.api import logger

from ....constants import (
    M_ROOM_ENCRYPTED,
    M_ROOM_KEY,
    MEGOLM_ALGO,
    PREFIX_CURVE25519,
    PREFIX_ED25519,
    SIGNED_CURVE25519,
)


class E2EEManagerSessionShareKeysLockedMixin:
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
            response = await self.client.query_keys(
                {user_id: [] for user_id in members}
            )
            device_keys = response.get("device_keys", {})
            if not isinstance(device_keys, dict):
                return 0

            member_set = set(members)
            devices_to_send: list[tuple[str, str, str, str]] = []
            for user_id, user_devices in device_keys.items():
                if user_id not in member_set or not isinstance(user_devices, dict):
                    continue
                for device_id, device_info in user_devices.items():
                    if user_id == self.user_id and device_id == self.device_id:
                        continue
                    if not self._olm.verify_device_keys(
                        user_id,
                        device_id,
                        device_info,
                    ):
                        logger.warning(
                            "Ignoring device with invalid Matrix self-signature: "
                            f"{user_id}/{device_id}"
                        )
                        continue

                    keys = device_info.get("keys", {})
                    curve_key = keys.get(f"{PREFIX_CURVE25519}{device_id}")
                    ed_key = keys.get(f"{PREFIX_ED25519}{device_id}")
                    if not isinstance(curve_key, str) or not isinstance(ed_key, str):
                        continue
                    if self._store:
                        self._store.save_device_keys(user_id, device_id, device_info)

                    cache_key = self._device_cache_key(user_id, device_id, curve_key)
                    if cache_key not in shared_devices:
                        devices_to_send.append((user_id, device_id, curve_key, ed_key))

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
                try:
                    # Membership/device callbacks may rotate this session while
                    # the network requests above are in flight.
                    if not self._outbound_session_is_current(room_id, session_id):
                        logger.debug("Room-key distribution stopped after rotation")
                        break

                    session = self._olm.get_olm_session(curve_key)
                    if not session:
                        device_otks = (one_time_keys.get(user_id) or {}).get(
                            device_id
                        ) or {}
                        selected = self._olm.select_verified_one_time_key(
                            user_id,
                            device_id,
                            ed_key,
                            device_otks,
                        )
                        if not selected:
                            logger.warning(
                                "No valid signed one-time key for "
                                f"{user_id}/{device_id}"
                            )
                            send_no_olm = getattr(
                                self,
                                "_send_no_olm_withheld",
                                None,
                            )
                            if callable(send_no_olm):
                                await send_no_olm(user_id, device_id)
                            continue
                        _, one_time_key = selected
                        session = self._olm.create_outbound_session(
                            curve_key,
                            one_time_key,
                        )

                    room_key_content = {
                        "algorithm": MEGOLM_ALGO,
                        "room_id": room_id,
                        "session_id": session_id,
                        "session_key": session_key,
                        "shared_history": shared_history,
                    }
                    encrypted_content = self._olm.encrypt_olm(
                        curve_key,
                        room_key_content,
                        session=session,
                        recipient_user_id=user_id,
                        recipient_ed25519_key=ed_key,
                        event_type=M_ROOM_KEY,
                    )
                    await self.client.send_to_device(
                        M_ROOM_ENCRYPTED,
                        {user_id: {device_id: encrypted_content}},
                        secrets.token_hex(16),
                    )
                    mark_succeeded = getattr(
                        self,
                        "_mark_olm_send_succeeded",
                        None,
                    )
                    if callable(mark_succeeded):
                        mark_succeeded(user_id, device_id)
                    shared_devices.add(
                        self._device_cache_key(user_id, device_id, curve_key)
                    )
                    sent_count += 1
                except Exception as e:
                    logger.warning(f"向 {user_id}/{device_id} 发送密钥失败：{e}")

            logger.info(
                f"已向 {sent_count}/{len(devices_to_send)} 个设备分发房间 {room_id} 的密钥 "
                f"(reason={reason})"
            )
            return sent_count
        except Exception as e:
            logger.error(f"密钥分发失败：{e}")
            return 0

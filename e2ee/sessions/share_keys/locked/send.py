"""Per-device room-key Olm encryption and delivery."""

import secrets

from astrbot.api import logger

from .....constants import M_ROOM_ENCRYPTED, M_ROOM_KEY, MEGOLM_ALGO


class E2EEManagerSessionShareKeysSendMixin:
    """Send an encrypted room key to one recipient device."""

    async def _send_room_key_to_device(
        self,
        user_id: str,
        device_id: str,
        curve_key: str,
        ed_key: str,
        *,
        room_id: str,
        session_id: str,
        session_key: str,
        shared_history: bool,
        one_time_keys: dict,
        shared_devices: set,
    ) -> bool | None:
        """Deliver the room key; None when the outbound session rotated."""
        try:
            # Membership/device callbacks may rotate this session while
            # the network requests above are in flight.
            if not self._outbound_session_is_current(room_id, session_id):
                logger.debug("Room-key distribution stopped after rotation")
                return None

            session = self._olm.get_olm_session(curve_key)
            if not session:
                device_otks = (one_time_keys.get(user_id) or {}).get(device_id) or {}
                selected = self._olm.select_verified_one_time_key(
                    user_id,
                    device_id,
                    ed_key,
                    device_otks,
                )
                if not selected:
                    logger.warning(
                        f"No valid signed one-time key for {user_id}/{device_id}"
                    )
                    send_no_olm = getattr(
                        self,
                        "_send_no_olm_withheld",
                        None,
                    )
                    if callable(send_no_olm):
                        await send_no_olm(user_id, device_id)
                    return False
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
            shared_devices.add(self._device_cache_key(user_id, device_id, curve_key))
            return True
        except Exception as e:
            logger.warning(f"向 {user_id}/{device_id} 发送密钥失败：{e}")
            return False

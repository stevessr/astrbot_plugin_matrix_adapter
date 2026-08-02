"""Proactive room-key distribution checks for the E2EE manager."""

from astrbot.api import logger


class E2EEManagerCoreKeySharingMixin:
    """主动检查并向需要的房间成员分发房间密钥。"""

    async def _proactive_check_key_sharing(self):
        """主动检查并分发房间密钥"""
        if self._closing or not self._olm or not self._initialized:
            return

        async with self._key_share_check_lock:
            try:
                room_ids = self._olm.get_megolm_outbound_room_ids()
                if not room_ids:
                    return

                affected_rooms = 0
                affected_devices = 0

                for room_id in room_ids:
                    members = await self._get_room_members(room_id)
                    if not members:
                        continue

                    session_info = self._olm.get_megolm_outbound_session_info(room_id)
                    if not session_info:
                        continue

                    session_id, session_key = session_info
                    sent_count = await self.ensure_room_keys_sent(
                        room_id=room_id,
                        members=members,
                        session_id=session_id,
                        session_key=session_key,
                        reason="proactive_check",
                    )
                    if sent_count:
                        affected_rooms += 1
                        affected_devices += sent_count

                if affected_rooms > 0:
                    logger.info(
                        f"主动密钥分发检查完成：rooms={affected_rooms} devices={affected_devices}"
                    )

            except Exception as e:
                logger.warning(f"主动密钥分发检查失败：{e}")

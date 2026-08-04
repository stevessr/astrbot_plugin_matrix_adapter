"""Establish a fresh outbound Olm session and send an encrypted dummy."""

import secrets

from astrbot.api import logger

from .....constants import (
    M_ROOM_ENCRYPTED,
    PREFIX_CURVE25519,
    PREFIX_ED25519,
    SIGNED_CURVE25519,
)
from ....constants import M_DUMMY


class E2EEManagerRequestsSessionEstablishMixin:
    """claim 一次性密钥、创建出站会话并发送 m.dummy。"""

    async def _establish_new_olm_session(
        self,
        target_user: str,
        target_device: str,
        sender_key: str,
    ) -> bool:
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

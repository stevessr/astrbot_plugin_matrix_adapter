"""
E2EE Manager verification helpers.
"""

from astrbot.api import logger

from ..constants import M_KEY_VERIFICATION_REQUEST, M_SAS_V1_METHOD, PREFIX_ED25519


class E2EEManagerVerificationMixin:
    async def handle_verification_event(
        self, event_type: str, sender: str, content: dict
    ) -> bool:
        """Handle verification events (m.key.verification.*)."""
        if self._verification:
            return await self._verification.handle_verification_event(
                event_type, sender, content
            )
        return False

    async def handle_in_room_verification_event(
        self,
        event_type: str,
        sender: str,
        content: dict,
        room_id: str,
        event_id: str,
    ) -> bool:
        """Handle in-room verification events."""
        if self._verification:
            return await self._verification.handle_in_room_verification_event(
                event_type, sender, content, room_id, event_id
            )
        return False

    async def _verify_untrusted_own_devices(self):
        """Query own devices and request verification for untrusted ones."""
        if not self._verification:
            return

        try:
            response = await self.client._request(
                "POST",
                "/_matrix/client/v3/keys/query",
                {"device_keys": {self.user_id: []}},
            )

            device_keys = response.get("device_keys", {}).get(self.user_id, {})
            if not device_keys:
                logger.debug("未找到其他设备")
                return

            verified_devices = set()
            if self._cross_signing and self._cross_signing._master_key:
                for device_id, keys in device_keys.items():
                    signatures = keys.get("signatures", {}).get(self.user_id, {})
                    for sig_key in signatures.keys():
                        if sig_key.startswith(PREFIX_ED25519):
                            verified_devices.add(device_id)
                            break

            untrusted_devices = []
            for device_id in device_keys.keys():
                if device_id == self.device_id:
                    continue
                if device_id not in verified_devices:
                    untrusted_devices.append(device_id)

            if not untrusted_devices:
                logger.info("所有其他设备已验证")
                return

            logger.info(f"发现 {len(untrusted_devices)} 个未验证设备，尝试发起验证...")

            for device_id in untrusted_devices:
                try:
                    await self._initiate_verification_for_device(device_id)
                except Exception as e:
                    logger.warning(f"无法为设备 {device_id} 发起验证：{e}")

        except Exception as e:
            logger.warning(f"查询设备验证状态失败：{e}")

    async def _initiate_verification_for_device(self, target_device_id: str):
        """Initiate SAS verification for device."""
        if not self._verification:
            return

        import secrets

        txn_id = secrets.token_hex(16)

        request_content = {
            "from_device": self.device_id,
            "methods": [M_SAS_V1_METHOD],
            "timestamp": int(__import__("time").time() * 1000),
            "transaction_id": txn_id,
        }

        await self.client.send_to_device(
            M_KEY_VERIFICATION_REQUEST,
            {self.user_id: {target_device_id: request_content}},
            txn_id,
        )

        if self._verification:
            self._verification.initiate_verification(
                txn_id, self.user_id, target_device_id
            )

        logger.info(f"已向设备 {target_device_id} 发起验证请求 (txn={txn_id[:8]}...)")

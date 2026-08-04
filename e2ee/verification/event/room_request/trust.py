"""Device fingerprint query and trust evaluation."""

from astrbot.api import logger

from .....constants import PREFIX_ED25519


class SASVerificationRoomRequestTrustMixin:
    """查询设备指纹并按 TOFU 策略评估信任。"""

    async def _query_device_fingerprint(self, sender: str, from_device: str):
        """返回设备 Ed25519 指纹，查询失败时返回 None。"""
        fingerprint = None
        try:
            # Query device keys to get the real fingerprint (Ed25519 key)
            logger.debug(f"[E2EE-Verify] Querying keys for {sender}|{from_device}")
            resp = await self.client.query_keys({sender: []})
            devices = resp.get("device_keys") or {}
            user_devices = devices.get(sender) or {}
            device_info = user_devices.get(from_device) or {}
            keys = device_info.get("keys") or {}
            # Key format: "ed25519:<device_id>"
            fingerprint = keys.get(f"{PREFIX_ED25519}{from_device}")
        except Exception as e:
            logger.warning(
                f"[E2EE-Verify] Failed to query keys for {sender}|{from_device}: {e}"
            )
        return fingerprint

    async def _evaluate_device_trust(
        self,
        session: dict,
        sender: str,
        from_device: str,
        fingerprint,
    ) -> bool:
        """评估设备信任；返回 False 时调用方应中止处理。"""
        if fingerprint:
            session["fingerprint"] = fingerprint
            if self.device_store.is_trusted(sender, from_device, fingerprint):
                logger.info(f"[E2EE-Verify] Trusted device {sender}|{from_device}")
            else:
                logger.info(
                    "[E2EE-Verify] Untrusted device "
                    f"{sender}|{from_device} (fingerprint: {(fingerprint or '')[:8]}...)"
                )

                # Notify user
                await self._notify_user_for_approval(
                    sender, from_device, session.get("room_id")
                )

                if self.auto_verify_mode == "auto_accept":
                    if self.trust_on_first_use:
                        logger.info(
                            "[E2EE-Verify] TOFU enabled: proceeding with auto-accept"
                        )
                    else:
                        logger.info(
                            "[E2EE-Verify] TOFU disabled: auto-accept disabled for untrusted device"
                        )
                        return False
        else:
            logger.warning(
                f"[E2EE-Verify] Could not find Ed25519 key for {sender}|{from_device}"
            )
            # If we can't find the key, we can't verify it properly.
            # But if TOFU is enabled, maybe we should proceed?
            # No, without a key we can't verify signatures anyway.
            # But the verification process itself exchanges keys.
            # Let's proceed but warn.
            if self.auto_verify_mode == "auto_accept" and not self.trust_on_first_use:
                logger.info(
                    "[E2EE-Verify] Key not found and TOFU disabled: aborting auto-accept"
                )
                return False

        return True

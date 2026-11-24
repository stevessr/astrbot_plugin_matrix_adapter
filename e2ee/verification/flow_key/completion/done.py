"""Verification completion persistence and trust publication."""

from astrbot.api import logger


class SASVerificationFlowDoneMixin:
    """处理 done 后的设备持久化与信任发布。"""

    async def _handle_done(self, sender: str, content: dict, transaction_id: str):
        """处理验证完成"""
        session = self._get_bound_verification_session(
            transaction_id,
            sender,
            content.get("from_device"),
        )
        if session is None:
            return

        logger.info(
            "[E2EE-Verify] ✅ 验证完成！"
            f"sender={self._mask_identifier(sender)} "
            f"txn={self._mask_txn_id(transaction_id)}"
        )

        qr_verified = bool(session.get("qr_confirmed"))
        if not session.get("mac_verified") and not qr_verified:
            logger.warning("[E2EE-Verify] 忽略 done：MAC/QR 尚未验证通过")
            return

        target_device = session.get("from_device") or session.get("their_device")
        if (
            session.get("qr_scanned_by_us")
            and target_device
            and not session.get("done_sent")
        ):
            session["done_sent"] = True
            is_in_room = session.get("is_in_room", False)
            room_id = session.get("room_id")
            if is_in_room and room_id:
                await self._send_in_room_done(room_id, transaction_id)
            else:
                await self._send_done(sender, target_device, transaction_id)
        session["state"] = "done"

        # 将设备标记为已验证
        from_device = target_device
        fingerprint = session.get("fingerprint")

        # If we didn't get fingerprint earlier, try to get it from the key exchange if possible,
        # or try query again?
        # The 'key' exchanged in SAS is the ephemeral key, not the device identity key.
        # But we should have fetched it in handle_request.

        if from_device and fingerprint:
            try:
                self.device_store.add_device(sender, from_device, fingerprint)
                logger.info(
                    "[E2EE-Verify] Device verified and saved: "
                    f"{self._mask_identifier(sender)}|"
                    f"{self._mask_identifier(from_device)}"
                )
            except Exception as e:
                logger.error(f"[E2EE-Verify] Failed to save verified device: {e}")
        else:
            logger.warning(
                "[E2EE-Verify] Cannot save device: missing info "
                f"(device={self._mask_identifier(from_device)}, "
                f"has_fingerprint={bool(fingerprint)})"
            )

        e2ee_manager = getattr(self, "e2ee_manager", None)
        if e2ee_manager and sender == self.user_id:
            publish_target = from_device or session.get("their_device")

            if publish_target:
                try:
                    await e2ee_manager.publish_trusted_device(sender, publish_target)
                except Exception as e:
                    logger.warning(
                        "[E2EE-Verify] 发布设备信任失败："
                        f"device={self._mask_identifier(publish_target)} err={e}"
                    )
            try:
                await e2ee_manager.request_missing_secrets_after_verification(sender)
            except Exception as e:
                logger.warning(f"[E2EE-Verify] 验证后请求缺失秘密失败：{e}")

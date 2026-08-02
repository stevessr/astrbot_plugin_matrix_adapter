from astrbot.api import logger


class SASVerificationDisplayNotificationsMixin:
    async def _notify_admin_for_verification(self, session: dict, transaction_id: str):
        sender = str(session.get("sender", "") or "").strip()
        device_id = str(
            session.get("from_device") or session.get("their_device") or ""
        ).strip()
        emojis = session.get("sas_emojis") or []
        decimals = str(session.get("sas_decimals") or "").strip()
        emoji_str = " ".join(e[0] for e in emojis) if emojis else ""

        lines = [
            "SAS 验证请求（手动确认）",
            f"用户：{sender}",
            f"设备：{device_id}",
        ]
        if emoji_str:
            lines.append(f"Emoji: {emoji_str}")
        if decimals:
            lines.append(f"数字：{decimals}")
        lines.append(f"事务：{transaction_id}")
        if sender and device_id:
            lines.append(f"使用命令：/approve_device {sender} {device_id}")

        message = "\n".join(lines)
        try:
            sent_count = await self._notify_admin_rooms_for_verification(
                message,
                transaction_id,
            )
            if sent_count > 0:
                logger.info(
                    "[E2EE-Verify] 手动验证通知已发送："
                    f"rooms={sent_count} txn={self._mask_txn_id(transaction_id)}"
                )
            else:
                logger.debug(
                    "[E2EE-Verify] 手动验证通知未发送（无目标房间）："
                    f"txn={self._mask_txn_id(transaction_id)}"
                )
        except Exception as e:
            logger.error(f"发送验证通知失败：{e}")

    async def _notify_admin_for_qr_code(self, session: dict, transaction_id: str):
        sender = str(session.get("sender", "") or "").strip()
        device_id = str(
            session.get("from_device") or session.get("their_device") or ""
        ).strip()
        qr_ascii = str(session.get("qr_ascii") or "").rstrip()
        mode = session.get("qr_mode")

        lines = [
            "QR 自验证已就绪",
            f"用户：{sender}",
            f"设备：{device_id}",
            f"事务：{transaction_id}",
        ]
        if mode is not None:
            lines.append(f"模式：0x{int(mode):02x}")
        lines.append("请在另一台已登录设备上选择“扫描二维码”来验证当前设备。")
        if qr_ascii:
            lines.extend(["", "```text", qr_ascii, "```"])

        message = "\n".join(lines)
        try:
            sent_count = await self._notify_admin_rooms_for_verification(
                message,
                transaction_id,
            )
            if sent_count > 0:
                logger.info(
                    "[E2EE-Verify] QR 验证通知已发送："
                    f"rooms={sent_count} txn={self._mask_txn_id(transaction_id)}"
                )
        except Exception as e:
            logger.error(f"发送 QR 验证通知失败：{e}")

    async def _notify_admin_for_qr_reciprocation(
        self, session: dict, transaction_id: str
    ):
        sender = str(session.get("sender", "") or "").strip()
        device_id = str(
            session.get("from_device") or session.get("their_device") or ""
        ).strip()
        lines = [
            "QR 已被对端扫描",
            f"用户：{sender}",
            f"设备：{device_id}",
            f"事务：{transaction_id}",
        ]
        if sender and device_id:
            lines.append(f"使用命令：/approve_device {sender} {device_id}")
        lines.append("确认另一设备已显示为已验证后，再完成当前设备确认。")

        message = "\n".join(lines)
        try:
            await self._notify_admin_rooms_for_verification(message, transaction_id)
        except Exception as e:
            logger.error(f"发送 QR 扫码确认通知失败：{e}")

    async def _notify_admin_to_scan_peer_qr(self, session: dict, transaction_id: str):
        sender = str(session.get("sender", "") or "").strip()
        device_id = str(
            session.get("from_device") or session.get("their_device") or ""
        ).strip()
        lines = [
            "对端支持展示 QR，自验证建议走扫码链路",
            f"用户：{sender}",
            f"设备：{device_id}",
            f"事务：{transaction_id}",
            "请在对端设备界面展示二维码后，使用 /scan_device_qr 扫码完成验证。",
        ]
        if sender and device_id:
            lines.append(
                f"命令：/scan_device_qr {sender} {device_id} <二维码图片路径或 base64 载荷>"
            )

        message = "\n".join(lines)
        try:
            await self._notify_admin_rooms_for_verification(message, transaction_id)
        except Exception as e:
            logger.error(f"发送扫码提示失败：{e}")

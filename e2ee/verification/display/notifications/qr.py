"""QR verification notifications."""

from astrbot.api import logger


class SASVerificationDisplayQRNotificationMixin:
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

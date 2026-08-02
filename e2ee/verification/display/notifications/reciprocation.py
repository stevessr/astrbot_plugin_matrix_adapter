"""QR reciprocation and peer-scan notifications."""

from astrbot.api import logger


class SASVerificationDisplayQRReciprocationNotificationMixin:
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

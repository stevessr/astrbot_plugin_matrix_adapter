import io

from astrbot.api import logger

from ..constants import (
    SAS_BYTES_LENGTH_6,
    SAS_EMOJI_COUNT_7,
)
from .verification_constants import (
    SAS_EMOJIS,
)


class SASVerificationDisplayMixin:
    @staticmethod
    def _build_terminal_qr(data: bytes) -> str | None:
        try:
            import qrcode
        except Exception:
            return None

        qr = qrcode.QRCode(border=1)
        qr.add_data(data)
        qr.make(fit=True)

        output = io.StringIO()
        qr.print_ascii(out=output, invert=True)
        return output.getvalue().strip("\n")

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

    async def _notify_user_for_approval(
        self, sender: str, device_id: str, room_id: str | None = None
    ):
        """ "Notify user for verification approval"""
        if not room_id:
            room_id = await self.client.get_user_room(sender)

        if room_id:
            message = (
                f"New device verification request from {sender} ({device_id}). "
                f"Please approve or deny."
            )
            await self.client.send_room_message(room_id, message)
        else:
            logger.warning(f"Could not find a room to notify {sender}")

    def _bytes_to_emoji(self, sas_bytes: bytes) -> list[tuple[str, str]]:
        """将 SAS 字节转换为 emoji"""
        bits = int.from_bytes(sas_bytes[:SAS_BYTES_LENGTH_6], "big")
        emojis = []
        for i in range(SAS_EMOJI_COUNT_7):
            idx = (bits >> (42 - i * 6)) & 0x3F
            emojis.append(SAS_EMOJIS[idx])
        return emojis

    def _bytes_to_decimal(self, sas_bytes: bytes) -> str:
        """将 SAS 字节转换为三组四位数字"""
        bits = int.from_bytes(sas_bytes[:5], "big")
        n1 = ((bits >> 27) & 0x1FFF) + 1000
        n2 = ((bits >> 14) & 0x1FFF) + 1000
        n3 = ((bits >> 1) & 0x1FFF) + 1000
        return f"{n1} {n2} {n3}"

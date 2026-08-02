"""Manual SAS verification notifications."""

from astrbot.api import logger


class SASVerificationDisplayManualNotificationMixin:
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

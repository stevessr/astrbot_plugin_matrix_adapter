"""Manual SAS or QR verification approval flow."""

from typing import Any


class SASVerificationApprovalMixin:
    """手动确认已完成 SAS 或 QR 交换的设备。"""

    async def approve_device(self, device_id: str) -> tuple[bool, str]:
        """手动确认某个设备的验证（SAS 或 QR）。"""
        terminal_states = getattr(
            self,
            "_TERMINAL_VERIFICATION_STATES",
            frozenset({"done", "cancelled", "handled_by_other_device"}),
        )
        candidates: list[tuple[str, dict[str, Any]]] = []
        for txn_id, session in self._sessions.items():
            if session.get("state") in terminal_states:
                continue
            if (
                session.get("from_device") == device_id
                or session.get("their_device") == device_id
            ):
                candidates.append((txn_id, session))

        if not candidates:
            return False, f"未找到设备 {device_id} 的待验证会话"

        # Prefer a flow which has actually reached a user-verifiable phase.
        txn_id, session = candidates[0]
        for tid, candidate_session in candidates:
            if (
                candidate_session.get("qr_reciprocated")
                or candidate_session.get("sas_emojis")
                or candidate_session.get("sas_decimals")
            ):
                txn_id, session = tid, candidate_session
                break

        sender = session.get("sender", "")
        target_device = (
            session.get("from_device") or session.get("their_device") or device_id
        )
        if not sender or not target_device:
            return False, "会话信息不完整，无法发送验证消息"

        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")

        qr_pending_confirm = bool(
            session.get("qr_reciprocated") and not session.get("qr_confirmed")
        )

        if qr_pending_confirm:
            try:
                session["qr_confirmed"] = True
                if not session.get("done_sent"):
                    if is_in_room and room_id:
                        await self._send_in_room_done(room_id, txn_id)
                    else:
                        await self._send_done(sender, target_device, txn_id)
                    session["done_sent"] = True
                session["state"] = "qr_confirmed"
            except Exception as e:
                return False, f"发送验证消息失败：{e}"
            return True, f"已发送 QR 验证确认（device_id={device_id}）"

        if not session.get("sas_emojis") and not session.get("sas_decimals"):
            return False, "SAS 尚未就绪，请稍后再试"

        # Human approval authorizes our MAC. It does not prove the peer MAC yet.
        # done is emitted only after both directions have cryptographically
        # completed, regardless of whether approval or the peer MAC arrives first.
        session["manual_approved"] = True
        try:
            if not session.get("mac_sent"):
                if is_in_room and room_id:
                    sent = await self._send_in_room_mac(room_id, txn_id, session)
                else:
                    sent = await self._send_mac(sender, target_device, txn_id, session)
                if sent is False:
                    return False, "无法发送 SAS MAC，请检查验证会话的密钥状态"
                session["mac_sent"] = True

            if session.get("mac_verified"):
                await self._send_mac_done(
                    session,
                    sender,
                    txn_id,
                    is_in_room,
                    room_id,
                )
        except Exception as e:
            return False, f"发送验证消息失败：{e}"

        if session.get("done_sent"):
            return True, f"SAS 双向验证完成（device_id={device_id}）"
        return True, f"已确认 SAS 并发送本端 MAC，等待对端 MAC（device_id={device_id}）"


__all__ = ["SASVerificationApprovalMixin"]

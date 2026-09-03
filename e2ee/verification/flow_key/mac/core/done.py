"""MAC verification success completion."""


class SASVerificationFlowMACDoneMixin:
    """Send the done event after successful MAC verification."""

    async def _send_mac_done(
        self,
        session: dict,
        sender: str,
        transaction_id: str,
        is_in_room: bool,
        room_id,
    ):
        should_finish = self.auto_verify_mode == "auto_accept" or (
            self.auto_verify_mode == "manual"
            and session.get("manual_approved")
            and session.get("mac_sent")
        )
        if not should_finish or not session.get("mac_verified") or session.get("done_sent"):
            return

        if is_in_room and room_id:
            await self._send_in_room_done(room_id, transaction_id)
        else:
            await self._send_done(
                sender,
                session.get("their_device") or session.get("from_device", ""),
                transaction_id,
            )
        session["done_sent"] = True

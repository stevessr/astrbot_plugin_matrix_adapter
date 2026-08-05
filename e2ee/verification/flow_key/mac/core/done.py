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
        if self.auto_verify_mode == "auto_accept" and not session.get("done_sent"):
            session["done_sent"] = True
            if is_in_room and room_id:
                await self._send_in_room_done(room_id, transaction_id)
            else:
                await self._send_done(
                    sender,
                    session.get("their_device", session.get("from_device", "")),
                    transaction_id,
                )

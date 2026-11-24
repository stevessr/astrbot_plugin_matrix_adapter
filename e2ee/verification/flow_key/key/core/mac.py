"""SAS MAC dispatch after key exchange."""


class SASVerificationFlowKeyMacMixin:
    """Send the MAC when auto-accepting the verification."""

    async def _send_sas_mac(
        self,
        session: dict,
        sender: str,
        transaction_id: str,
        *,
        is_in_room: bool,
        room_id: str | None,
        their_device: str,
    ) -> None:
        if self.auto_verify_mode != "auto_accept" or session.get("mac_sent"):
            return

        if is_in_room and room_id:
            sent = await self._send_in_room_mac(room_id, transaction_id, session)
        else:
            sent = await self._send_mac(
                sender,
                their_device,
                transaction_id,
                session,
            )
        if sent is not False:
            session["mac_sent"] = True


__all__ = ["SASVerificationFlowKeyMacMixin"]

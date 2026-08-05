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
        # Send MAC only if not already sent
        if self.auto_verify_mode == "auto_accept" and not session.get("mac_sent"):
            session["mac_sent"] = True
            if is_in_room and room_id:
                await self._send_in_room_mac(room_id, transaction_id, session)
            else:
                await self._send_mac(
                    sender,
                    their_device,
                    transaction_id,
                    session,
                )


__all__ = ["SASVerificationFlowKeyMacMixin"]

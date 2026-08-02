from astrbot.api import logger


class SASVerificationDisplayApprovalMixin:
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

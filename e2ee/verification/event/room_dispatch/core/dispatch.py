"""In-room verification event routing."""

from ......constants import (
    M_KEY_VERIFICATION_ACCEPT,
    M_KEY_VERIFICATION_CANCEL,
    M_KEY_VERIFICATION_DONE,
    M_KEY_VERIFICATION_KEY,
    M_KEY_VERIFICATION_MAC,
    M_KEY_VERIFICATION_READY,
    M_KEY_VERIFICATION_REQUEST,
    M_KEY_VERIFICATION_START,
)


class SASVerificationRoomEventDispatchRouteMixin:
    """Route in-room verification events to their handlers."""

    async def _route_in_room_event(
        self,
        event_type: str,
        sender: str,
        content: dict,
        transaction_id: str,
        is_verification_request: bool,
    ) -> bool | None:
        """Dispatch to the matching handler; None means not handled here."""
        # Check if this event is from our own user
        if sender == self.user_id:
            handled = await self._handle_own_user_room_event(
                sender,
                event_type,
                content,
                transaction_id,
            )
            if handled is not None:
                return handled

        handlers = {
            M_KEY_VERIFICATION_REQUEST: self._handle_in_room_request,
            M_KEY_VERIFICATION_READY: self._handle_ready,
            M_KEY_VERIFICATION_START: self._handle_start,
            M_KEY_VERIFICATION_ACCEPT: self._handle_accept,
            M_KEY_VERIFICATION_KEY: self._handle_key,
            M_KEY_VERIFICATION_MAC: self._handle_mac,
            M_KEY_VERIFICATION_DONE: self._handle_done,
            M_KEY_VERIFICATION_CANCEL: self._handle_cancel,
        }

        # For verification requests (m.room.message with msgtype m.key.verification.request),
        # use _handle_in_room_request directly
        if is_verification_request:
            await self._handle_in_room_request(sender, content, transaction_id)
            return True

        handler = handlers.get(event_type)
        if handler:
            await handler(sender, content, transaction_id)
            return True
        return False


__all__ = ["SASVerificationRoomEventDispatchRouteMixin"]

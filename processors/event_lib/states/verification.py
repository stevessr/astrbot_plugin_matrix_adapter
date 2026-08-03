"""In-room verification event handling."""

from astrbot.api import logger


class MatrixEventProcessorVerificationMixin:
    """Forward in-room verification events to the E2EE manager."""

    async def _handle_in_room_verification(self, room, event_data: dict):
        """
        Handle in-room verification events (m.key.verification.*)

        Args:
            room: Room object
            event_data: Event data
        """
        event_type = event_data.get("type")
        sender = event_data.get("sender")
        content = event_data.get("content", {})
        event_id = event_data.get("event_id")

        # 验证必需字段
        if not isinstance(sender, str) or not sender:
            logger.debug(
                f"房间内验证事件缺少 sender：type={event_type}, event_id={event_id}"
            )
            return

        if not event_type or not event_id:
            logger.debug(
                f"房间内验证事件缺少必需字段：type={event_type}, sender={sender}, event_id={event_id}"
            )
            return

        # Ignore events from self, UNLESS it's from a different device (verification request)
        if sender == self.user_id:
            from_device = content.get("from_device")
            # For events that don't have from_device (like cancel, done, mac, key),
            # we need to check if we have a matching session where we're the responder
            if not from_device:
                # For cancel/done events from self without from_device, it's likely our own echo
                # Only ignore if we don't have an active session as a responder
                if event_type in (
                    "m.key.verification.cancel",
                    "m.key.verification.done",
                ):
                    return
            elif self.e2ee_manager and from_device == self.e2ee_manager.device_id:
                # from_device matches our device_id, definitely our own echo
                return
            # If from_device is different, proceed (it's from another session of the same user)

        if self.e2ee_manager:
            try:
                # Forward to E2EE manager with room_id for in-room response
                await self.e2ee_manager.handle_in_room_verification_event(
                    event_type=event_type,
                    sender=sender,
                    content=content,
                    room_id=room.room_id,
                    event_id=event_id,
                )
            except Exception as e:
                logger.error(f"处理房间内验证事件失败：{e}")
        else:
            logger.warning("E2EE 未启用，忽略房间内验证事件")

"""In-room verification event handling entry point."""

from astrbot.api import logger


class SASVerificationRoomEventDispatchOrchestratorMixin:
    """Orchestrate in-room verification event handling."""

    async def handle_in_room_verification_event(
        self, event_type: str, sender: str, content: dict, room_id: str, event_id: str
    ) -> bool:
        """处理房间内验证事件"""
        is_verification_request, transaction_id = self._extract_in_room_event_context(
            event_type,
            sender,
            content,
            room_id,
            event_id,
        )

        if not transaction_id:
            logger.warning(
                f"[E2EE-Verify] 房间内验证事件缺少 transaction_id: "
                f"type={event_type}, sender={sender}"
            )
            return False

        logger.debug(
            f"[E2EE-Verify] 收到房间内验证事件：{event_type} "
            f"from={sender} room={(room_id or '')[:16]}... txn={(transaction_id or '')[:16]}..."
        )

        # Only an actual verification request may create an in-room session.
        if self._prepare_in_room_session(
            transaction_id,
            room_id,
            event_type,
            is_verification_request,
        ):
            return True

        return await self._route_in_room_event(
            event_type,
            sender,
            content,
            transaction_id,
            is_verification_request,
        )


__all__ = ["SASVerificationRoomEventDispatchOrchestratorMixin"]

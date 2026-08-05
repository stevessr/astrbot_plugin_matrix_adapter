"""Room member summary-count fallback for event dispatch."""

from astrbot.api import logger


class MatrixEventProcessorRoomMembersFallbackMixin:
    """Apply /sync summary member counts as a fallback."""

    def _apply_summary_member_count(
        self,
        room_id: str,
        room,
        room_data: dict,
    ) -> None:
        """Fall back to /sync summary counts after a member fetch failure."""
        # Final fallback: use /sync summary counts
        summary = room_data.get("summary", {})
        joined_count = summary.get("joined_member_count")
        invited_count = summary.get("invited_member_count")
        if isinstance(joined_count, int):
            room.member_count = joined_count + (
                invited_count if isinstance(invited_count, int) else 0
            )
            logger.warning(
                f"房间 {room_id} 使用备用方案（summary）: "
                f"joined={joined_count}, invited={invited_count}, "
                f"total={room.member_count}"
            )


__all__ = ["MatrixEventProcessorRoomMembersFallbackMixin"]

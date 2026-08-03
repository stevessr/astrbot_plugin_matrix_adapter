"""Room event lookup helpers for Matrix reactions."""

from .platform import MatrixUtilsReactionPlatformMixin


class MatrixUtilsReactionEventsMixin:
    """Find Matrix events that should receive a reaction."""

    @staticmethod
    async def find_event_for_reaction(
        context,
        room_id: str,
        message_content: str,
        *,
        time: object | None = None,
        platform_id: str = "",
        fallback_to_first: bool = True,
        limit: int = 100,
    ) -> dict | None:
        """Find the nearest room event matching ``message_content`` near ``time``."""
        from ...reaction_helpers import (
            find_room_event_for_reaction,
            parse_reaction_anchor_time_ms,
        )

        target_room_id = str(room_id or "").strip()
        query = str(message_content or "").strip()
        if not target_room_id:
            raise ValueError("room_id is required")
        if not query:
            raise ValueError("message_content is required")

        client = MatrixUtilsReactionPlatformMixin.get_matrix_client(
            context,
            str(platform_id or "").strip(),
            fallback_to_first=bool(
                fallback_to_first and not str(platform_id or "").strip()
            ),
        )
        if client is None:
            suffix = f" {platform_id!r}" if str(platform_id or "").strip() else ""
            raise RuntimeError(f"Matrix adapter{suffix} is not available")

        return await find_room_event_for_reaction(
            client,
            target_room_id,
            query,
            anchor_time_ms=parse_reaction_anchor_time_ms(time),
            limit=limit,
        )

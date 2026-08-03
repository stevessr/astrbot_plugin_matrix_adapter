"""Reaction dispatch helpers for Matrix adapters."""

from .keys import MatrixUtilsReactionKeysMixin
from .platform import MatrixUtilsReactionPlatformMixin


class MatrixUtilsReactionSendMixin:
    """Send resolved reactions through a Matrix adapter."""

    @staticmethod
    async def send_reaction(
        context,
        room_id: str,
        event_id: str,
        reaction: str,
        *,
        platform_id: str = "",
        fallback_to_first: bool = True,
        resolve_key: bool = True,
        event=None,
    ) -> dict:
        """Send a reaction through a running Matrix adapter.

        This is the stable entry point for other AstrBot plugins that need to react
        to an arbitrary Matrix event without retaining adapter internals.

        Args:
            context: AstrBot plugin context containing the platform manager.
            room_id: Matrix room ID containing the target event.
            event_id: Matrix event ID to annotate.
            reaction: Unicode emoji, emoji shortcode, sticker shortcode, or custom
                Matrix reaction key (including ``mxc://`` custom emotes).
            platform_id: Optional AstrBot Matrix platform instance ID.
            fallback_to_first: Use the first Matrix adapter only when ``platform_id``
                is empty.
            resolve_key: When true, resolve shortcodes via registered resolvers.
            event: Optional AstrMessageEvent passed to reaction-key resolvers.

        Returns:
            Matrix homeserver response containing the reaction event ID.

        Raises:
            ValueError: If a required Matrix identifier or reaction is empty.
            RuntimeError: If no matching adapter or reaction sender is available.
        """
        target_room_id = str(room_id or "").strip()
        target_event_id = str(event_id or "").strip()
        reaction_key = str(reaction or "").strip()
        target_platform_id = str(platform_id or "").strip()
        if not target_room_id:
            raise ValueError("room_id is required")
        if not target_event_id:
            raise ValueError("event_id is required")
        if not reaction_key:
            raise ValueError("reaction is required")

        if resolve_key:
            reaction_key = await MatrixUtilsReactionKeysMixin.resolve_reaction_key(
                reaction_key,
                context=context,
                room_id=target_room_id,
                platform_id=target_platform_id,
                event=event,
            )
            reaction_key = str(reaction_key or "").strip()
            if not reaction_key:
                raise ValueError("reaction is required")

        platform = MatrixUtilsReactionPlatformMixin.get_matrix_platform(
            context,
            target_platform_id,
            fallback_to_first=bool(fallback_to_first and not target_platform_id),
        )
        if platform is None:
            suffix = f" {target_platform_id!r}" if target_platform_id else ""
            raise RuntimeError(f"Matrix adapter{suffix} is not available")

        sender = getattr(platform, "sender", None)
        send_reaction = getattr(sender, "send_reaction", None)
        if not callable(send_reaction):
            client = getattr(platform, "client", None)
            send_reaction = getattr(client, "send_reaction", None)
        if not callable(send_reaction):
            raise RuntimeError("Matrix reaction sender is not available")

        return await send_reaction(target_room_id, target_event_id, reaction_key)

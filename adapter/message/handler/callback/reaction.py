"""Reaction handling for inbound message callbacks."""

from astrbot.api import logger


async def _handle_reaction_event(
    adapter, room, event, sender_id: str, sender_name: str
):
    """Format a reaction into a debug line; reactions never enter the pipeline."""
    # Reactions should not enter the normal pipeline to avoid LLM replies.
    try:
        relates_to = event.content.get("m.relates_to", {})
        emoji = relates_to.get("key") or event.body or ""
        target = relates_to.get("event_id", "")
        target_summary = ""
        if target:
            target_summary = await adapter._resolve_reaction_target_summary(
                room, target
            )
        if emoji and target:
            text = f"[reaction] {emoji} -> {target}"
        elif emoji:
            text = f"[reaction] {emoji}"
        elif target:
            text = f"[reaction] -> {target}"
        else:
            text = "[reaction]"
        if target_summary:
            text = f"{text} ({target_summary})"
        # Reaction 日志改为 debug，以减少高频 info 输出
        logger.debug(f"[matrix(matrix)] {sender_name}/{sender_id}: {text}")
    except Exception:
        pass


__all__ = ["_handle_reaction_event"]

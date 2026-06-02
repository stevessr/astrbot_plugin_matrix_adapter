from astrbot.api import logger


def _copy_cleartext_relates_to(encrypted: dict, content: dict) -> dict:
    """Expose relation metadata on encrypted events for aggregation."""
    relates_to = content.get("m.relates_to")
    if isinstance(encrypted, dict) and isinstance(relates_to, dict):
        encrypted.setdefault("m.relates_to", dict(relates_to))
    return encrypted


async def send_content(
    client,
    content: dict,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    msg_type: str = "m.room.message",
) -> dict | None:
    if use_thread and thread_root:
        is_reply_within_thread = reply_to is not None
        content["m.relates_to"] = {
            "rel_type": "m.thread",
            "event_id": thread_root,
            "is_falling_back": not is_reply_within_thread,
            "m.in_reply_to": {"event_id": reply_to or thread_root},
        }
    elif reply_to:
        content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}

    if is_encrypted_room and e2ee_manager:
        encrypted = await e2ee_manager.encrypt_message(room_id, msg_type, content)
        if encrypted:
            _copy_cleartext_relates_to(encrypted, content)
            return await client.send_message(
                room_id=room_id,
                msg_type="m.room.encrypted",
                content=encrypted,
            )
        logger.warning("加密消息失败，尝试发送未加密消息")

    return await client.send_message(
        room_id=room_id, msg_type=msg_type, content=content
    )

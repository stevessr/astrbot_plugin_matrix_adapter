from astrbot.api import logger


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
) -> None:
    if use_thread and thread_root:
        content["m.relates_to"] = {
            "rel_type": "m.thread",
            "event_id": thread_root,
            "m.in_reply_to": {"event_id": reply_to} if reply_to else None,
        }
    elif reply_to:
        content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}

    if is_encrypted_room and e2ee_manager:
        encrypted = await e2ee_manager.encrypt_message(room_id, msg_type, content)
        if encrypted:
            await client.send_message(
                room_id=room_id,
                msg_type="m.room.encrypted",
                content=encrypted,
            )
            return
        logger.warning("加密消息失败，尝试发送未加密消息")

    await client.send_message(room_id=room_id, msg_type=msg_type, content=content)

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
) -> dict | None:
    if use_thread and thread_root:
        relates_to = {
            "rel_type": "m.thread",
            "event_id": thread_root,
        }
        # 根据 Matrix 规范，为不支持线程的客户端提供回退
        if reply_to:
            relates_to["m.in_reply_to"] = {"event_id": reply_to}
            relates_to["is_falling_back"] = True
        content["m.relates_to"] = relates_to
    elif reply_to:
        content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}

    if is_encrypted_room and e2ee_manager:
        encrypted = await e2ee_manager.encrypt_message(room_id, msg_type, content)
        if encrypted:
            return await client.send_message(
                room_id=room_id,
                msg_type="m.room.encrypted",
                content=encrypted,
            )
        logger.warning("加密消息失败，尝试发送未加密消息")

    return await client.send_message(
        room_id=room_id, msg_type=msg_type, content=content
    )

from astrbot.api.message_components import At

from .common import send_content


async def send_at(
    client,
    segment: At,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
) -> None:
    user_id = str(segment.qq)
    if user_id == "all":
        content = {
            "msgtype": "m.text",
            "body": "@room",
            "m.mentions": {"room": True},
        }
    else:
        if not user_id.startswith("@"):
            user_id = f"@{user_id}"
        display = segment.name or user_id
        if not display.startswith("@"):
            display = f"@{display}"
        formatted_body = f'<a href="https://matrix.to/#/{user_id}" data-mxid="{user_id}">{display}</a>'
        content = {
            "msgtype": "m.text",
            "body": display,
            "format": "org.matrix.custom.html",
            "formatted_body": formatted_body,
            "m.mentions": {"user_ids": [user_id]},
        }

    await send_content(
        client,
        content,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
    )

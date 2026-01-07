from astrbot.api.message_components import Contact

from .common import send_content


async def send_contact(
    client,
    segment: Contact,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
) -> None:
    contact_type = getattr(segment, "_type", "") or ""
    contact_id = getattr(segment, "id", "") or ""
    body = f"[contact] type={contact_type} id={contact_id}".strip()
    content_data = {"msgtype": "m.text", "body": body}

    if isinstance(contact_id, str) and contact_id.startswith("@") and ":" in contact_id:
        link = f"https://matrix.to/#/{contact_id}"
        display = contact_id
        content_data = {
            "msgtype": "m.text",
            "body": display,
            "format": "org.matrix.custom.html",
            "formatted_body": f'<a href="{link}">{display}</a>',
            "m.mentions": {"user_ids": [contact_id]},
        }

    await send_content(
        client,
        content_data,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
    )

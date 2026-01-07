from astrbot.api.message_components import Location

from .common import send_content


async def send_location(
    client,
    segment: Location,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
) -> None:
    geo_uri = f"geo:{segment.lat},{segment.lon}"
    body = segment.title or segment.content or geo_uri
    content = {"msgtype": "m.location", "body": body, "geo_uri": geo_uri}

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

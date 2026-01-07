from astrbot.api.message_components import Music

from .common import send_content


async def send_music(
    client,
    segment: Music,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
) -> None:
    title = segment.title or ""
    content = segment.content or ""
    url = segment.url or ""
    audio = segment.audio or ""
    image = segment.image or ""

    lines = [line for line in [title, content, url, audio, image] if line]
    body = "\n".join(lines) if lines else "[music]"

    if url:
        link_title = title or url
        formatted = f'<a href="{url}">{link_title}</a>'
        if content:
            formatted = f"{formatted}<br>{content}"
        if audio:
            formatted = f"{formatted}<br>{audio}"
        if image:
            formatted = f"{formatted}<br>{image}"
        content_data = {
            "msgtype": "m.text",
            "body": body,
            "format": "org.matrix.custom.html",
            "formatted_body": formatted,
        }
    else:
        content_data = {"msgtype": "m.text", "body": body}

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

import html

from astrbot.api.message_components import Share

from ...constants import MATRIX_HTML_FORMAT
from .common import resolve_text_msgtype, send_content


async def send_share(
    client,
    segment: Share,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    thread_is_falling_back: bool | None = None,
    use_notice: bool = False,
) -> None:
    msgtype = resolve_text_msgtype(use_notice)
    title = segment.title or ""
    content = segment.content or ""
    url = segment.url or ""
    image = segment.image or ""

    lines = [line for line in [title, content, url, image] if line]
    body = "\n".join(lines) if lines else "[share]"

    if url:
        link_title = title or url
        formatted = (
            f'<a href="{html.escape(url, quote=True)}">'
            f"{html.escape(link_title)}</a>"
        )
        if content:
            formatted = f"{formatted}<br>{html.escape(content)}"
        if image:
            formatted = f"{formatted}<br>{html.escape(image)}"
        content_data = {
            "msgtype": msgtype,
            "body": body,
            "format": MATRIX_HTML_FORMAT,
            "formatted_body": formatted,
        }
    else:
        content_data = {"msgtype": msgtype, "body": body}

    await send_content(
        client,
        content_data,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
        thread_is_falling_back=thread_is_falling_back,
    )

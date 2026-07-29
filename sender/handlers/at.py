import html
from urllib.parse import quote

from astrbot.api.message_components import At

from ...constants import M_MENTIONS_KEY, MATRIX_HTML_FORMAT
from .common import resolve_text_msgtype, send_content


async def send_at(
    client,
    segment: At,
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
    user_id = str(segment.qq)
    if user_id == "all":
        content = {
            "msgtype": msgtype,
            "body": "@room",
            "m.mentions": {"room": True},
        }
    else:
        if not user_id.startswith("@"):
            user_id = f"@{user_id}"
        display = segment.name or user_id
        if not display.startswith("@"):
            display = f"@{display}"
        matrix_to_url = f"https://matrix.to/#/{quote(user_id, safe='')}"
        formatted_body = (
            f'<a href="{html.escape(matrix_to_url, quote=True)}" '
            f'data-mxid="{html.escape(user_id, quote=True)}">'
            f"{html.escape(display)}</a>"
        )
        content = {
            "msgtype": msgtype,
            "body": display,
            "format": MATRIX_HTML_FORMAT,
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
        thread_is_falling_back=thread_is_falling_back,
    )

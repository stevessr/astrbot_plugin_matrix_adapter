from astrbot.api.message_components import Shake

from .common import send_content


async def send_shake(
    client,
    segment: Shake,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
) -> None:
    content_data = {"msgtype": "m.emote", "body": "shakes the chat"}

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

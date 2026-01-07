import random

from astrbot.api.message_components import Dice

from .common import send_content


async def send_dice(
    client,
    segment: Dice,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
) -> None:
    roll = random.randint(1, 6)
    content_data = {"msgtype": "m.text", "body": f"[dice] {roll}"}

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

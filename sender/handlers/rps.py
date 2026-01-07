import random

from astrbot.api.message_components import RPS

from .common import send_content


async def send_rps(
    client,
    segment: RPS,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
) -> None:
    choices = ["rock", "paper", "scissors"]
    choice = random.choice(choices)
    content_data = {"msgtype": "m.text", "body": f"[rps] {choice}"}

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

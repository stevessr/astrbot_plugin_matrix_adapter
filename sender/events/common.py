from astrbot.api import logger

from ...constants import M_MENTIONS_KEY, M_ROOM_ENCRYPTED, M_ROOM_MESSAGE


def resolve_text_msgtype(use_notice: bool = False) -> str:
    """Resolve the Matrix ``msgtype`` for textual adapter output."""
    return "m.notice" if use_notice else "m.text"


def _ensure_intentional_mentions(content: dict, msg_type: str) -> None:
    """Mark outbound room messages as intentional-mentions aware.

    Matrix v1.17 / MSC4210 removes legacy plaintext mentions. Clients that
    understand ``m.mentions`` must still include an empty object when a message
    intentionally mentions nobody, otherwise compatibility clients may treat
    the event as using the removed legacy mention semantics.
    """
    if msg_type != M_ROOM_MESSAGE or not isinstance(content, dict):
        return
    if not isinstance(content.get(M_MENTIONS_KEY), dict):
        content[M_MENTIONS_KEY] = {}


def _copy_cleartext_relates_to(encrypted: dict, content: dict) -> dict:
    """Expose relation metadata on encrypted events for aggregation."""
    relates_to = content.get("m.relates_to")
    if isinstance(encrypted, dict) and isinstance(relates_to, dict):
        encrypted.setdefault("m.relates_to", dict(relates_to))
    return encrypted


async def send_content(
    client,
    content: dict,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    msg_type: str = M_ROOM_MESSAGE,
    thread_is_falling_back: bool | None = None,
) -> dict | None:
    _ensure_intentional_mentions(content, msg_type)

    if use_thread and thread_root:
        # A thread fallback still points to the latest known event, so target
        # presence alone cannot distinguish it from an explicit thread reply.
        if thread_is_falling_back is None:
            thread_is_falling_back = reply_to is None
        content["m.relates_to"] = {
            "rel_type": "m.thread",
            "event_id": thread_root,
            "is_falling_back": bool(thread_is_falling_back),
            "m.in_reply_to": {"event_id": reply_to or thread_root},
        }
    elif reply_to:
        content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}

    if is_encrypted_room and e2ee_manager:
        encrypted = await e2ee_manager.encrypt_message(room_id, msg_type, content)
        if encrypted:
            _copy_cleartext_relates_to(encrypted, content)
            return await client.send_message(
                room_id=room_id,
                msg_type=M_ROOM_ENCRYPTED,
                content=encrypted,
            )
        logger.warning("加密消息失败，尝试发送未加密消息")

    return await client.send_message(
        room_id=room_id, msg_type=msg_type, content=content
    )

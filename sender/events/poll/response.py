"""Matrix poll response event sender."""

from collections.abc import Awaitable, Callable

from ....constants import CONTENT_KEY_RELATES_TO, REL_TYPE_REFERENCE
from ..common import send_content as _default_send_content

SendContent = Callable[..., Awaitable[dict | None]]


async def _send_poll_response(
    client,
    room_id: str,
    poll_start_event_id: str,
    answer_ids: list[str],
    event_type: str = "m.poll.response",
    poll_key: str = "m.poll",
    *,
    send_content_fn: SendContent | None = None,
) -> dict | None:
    """Send a response to an existing poll.

    Args:
        client: Matrix HTTP client
        room_id: Room ID
        poll_start_event_id: The event ID of the poll start event
        answer_ids: List of answer IDs to vote for
        event_type: Event type to use (m.poll.response or org.matrix.msc3381.poll.response)
        poll_key: Poll key to use (m.poll or org.matrix.msc3381.poll.response)

    Returns:
        The response from the server, or None on failure
    """
    if not poll_start_event_id:
        raise ValueError("poll_start_event_id is required for poll response")

    clean_answer_ids = [str(a).strip() for a in (answer_ids or []) if str(a).strip()]
    if not clean_answer_ids:
        raise ValueError("at least one answer_id is required for poll response")

    use_msc3381 = bool(
        (event_type or "").startswith("org.matrix.msc3381.")
        or (poll_key or "").startswith("org.matrix.msc3381.")
    )

    if use_msc3381:
        content = {
            poll_key: {
                "answers": clean_answer_ids,
            }
        }
    else:
        content = {"m.selections": clean_answer_ids}

    # Poll responses reference the corresponding poll start event.
    content[CONTENT_KEY_RELATES_TO] = {
        "rel_type": REL_TYPE_REFERENCE,
        "event_id": poll_start_event_id,
    }

    sender = send_content_fn or _default_send_content
    return await sender(
        client,
        content,
        room_id,
        reply_to=None,
        thread_root=None,
        use_thread=False,
        is_encrypted_room=False,  # Poll responses are typically not encrypted separately
        e2ee_manager=None,
        msg_type=event_type,
    )

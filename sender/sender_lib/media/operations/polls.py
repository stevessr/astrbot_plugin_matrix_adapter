"""Matrix poll send and response operations."""


class SenderMediaPollsMixin:
    """Delegate Matrix poll operations."""

    async def send_poll(
        self,
        room_id: str,
        question: str,
        answers: list[str],
        max_selections: int = 1,
        kind: str = "m.disclosed",
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
        event_type: str = "m.poll.start",
        poll_key: str = "m.poll",
        fallback_text: str | None = None,
        fallback_html: str | None = None,
    ) -> dict | None:
        """Send a poll to a room."""
        from ....events import send_poll

        is_encrypted_room = False
        if self.e2ee_manager:
            try:
                is_encrypted_room = await self.client.is_room_encrypted(room_id)
            except Exception:
                is_encrypted_room = False

        return await send_poll(
            self.client,
            room_id,
            question,
            answers,
            reply_to,
            thread_root,
            use_thread,
            is_encrypted_room,
            self.e2ee_manager,
            max_selections=max_selections,
            kind=kind,
            event_type=event_type,
            poll_key=poll_key,
            fallback_text=fallback_text,
            fallback_html=fallback_html,
        )

    async def send_poll_response(
        self,
        room_id: str,
        poll_start_event_id: str,
        answer_ids: list[str],
        event_type: str = "m.poll.response",
        poll_key: str = "m.poll",
    ) -> dict | None:
        """Send a response to an existing poll.

        Args:
            room_id: Room ID
            poll_start_event_id: The event ID of the poll start event
            answer_ids: List of answer IDs to vote for.
                Stable polls use IDs like ["answer_1"], while MSC3381 polls
                usually use ["1"].
            event_type: Event type to use (m.poll.response or org.matrix.msc3381.poll.response)
            poll_key: Poll key to use (m.poll or org.matrix.msc3381.poll.response)

        Returns:
            The response from the server, or None on failure
        """
        from ....events import send_poll_response

        return await send_poll_response(
            self.client,
            room_id,
            poll_start_event_id,
            answer_ids,
            event_type=event_type,
            poll_key=poll_key,
        )

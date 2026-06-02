"""
Matrix 消息发送组件
"""

from typing import Any

from astrbot.api.event import MessageChain
from astrbot.api.message_components import Record, Video

from ..constants import (
    M_BEACON,
    M_BEACON_INFO,
    M_PROFILE_KEY,
    MSC1767_TEXT_KEY,
    MSC3488_ASSET_KEY,
    MSC3488_TS_KEY,
    MSC4144_PROFILE_KEY,
)

# Update import: markdown_utils is now in ..utils.markdown_utils


class MatrixSender:
    def __init__(self, client, e2ee_manager=None):
        self.client = client
        self.e2ee_manager = e2ee_manager

    async def send_message(
        self,
        room_id: str,
        message_chain: MessageChain,
        reply_to: str = None,
        thread_root: str = None,
        use_thread: bool = False,
        use_notice: bool = False,
    ) -> int:
        """
        Send a message to a room
        """
        from ..matrix_event import MatrixPlatformEvent

        return await MatrixPlatformEvent.send_with_client(
            self.client,
            message_chain,
            room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            e2ee_manager=self.e2ee_manager,
            use_notice=use_notice,
        )

    async def send_video(
        self,
        room_id: str,
        video: str,
        reply_to: str = None,
        thread_root: str = None,
        use_thread: bool = False,
        use_notice: bool = False,
    ) -> int:
        """Send a video to a room (file path or http/https URL)."""
        if video.startswith("http://") or video.startswith("https://"):
            segment = Video.fromURL(video)
        else:
            segment = Video.fromFileSystem(video)
        return await self.send_message(
            room_id,
            MessageChain([segment]),
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            use_notice=use_notice,
        )

    async def send_audio(
        self,
        room_id: str,
        audio: str,
        reply_to: str = None,
        thread_root: str = None,
        use_thread: bool = False,
        use_notice: bool = False,
    ) -> int:
        """Send an audio clip to a room (file path or http/https URL)."""
        if audio.startswith("http://") or audio.startswith("https://"):
            segment = Record.fromURL(audio)
        else:
            segment = Record.fromFileSystem(audio)
        return await self.send_message(
            room_id,
            MessageChain([segment]),
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            use_notice=use_notice,
        )

    async def send_custom_message(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
    ) -> dict | None:
        """
        Send a custom Matrix room event.

        Args:
            room_id: Room ID
            event_type: Matrix event type, e.g. `m.room.message` or `org.example.custom`
            content: Event content dictionary
            reply_to: Optional event ID to reply to
            thread_root: Optional thread root event ID
            use_thread: Whether to send as threaded event

        Returns:
            Matrix API response (usually containing event_id), or None on failure
        """
        if not event_type or not isinstance(event_type, str):
            raise ValueError("event_type must be a non-empty string")
        if not isinstance(content, dict):
            raise ValueError("content must be a dict")

        from .handlers.common import send_content

        is_encrypted_room = False
        if self.e2ee_manager:
            try:
                is_encrypted_room = await self.client.is_room_encrypted(room_id)
            except Exception:
                is_encrypted_room = False

        return await send_content(
            client=self.client,
            content=dict(content),
            room_id=room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            is_encrypted_room=is_encrypted_room,
            e2ee_manager=self.e2ee_manager,
            msg_type=event_type,
        )

    async def send_custom_event(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
    ) -> dict | None:
        """Alias of send_custom_message."""
        return await self.send_custom_message(
            room_id=room_id,
            event_type=event_type,
            content=content,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
        )

    async def send_reaction(self, room_id: str, event_id: str, emoji: str) -> dict:
        """Send a reaction to a message in a room."""
        return await self.client.send_reaction(room_id, event_id, emoji)

    async def send_receipt(
        self,
        room_id: str,
        event_id: str,
        receipt_type: str = "m.read",
        thread_id: str | None = None,
    ) -> dict:
        """Send a read/private-read receipt for a room event."""
        if receipt_type == "m.read.private":
            return await self.client.send_read_receipt_private(
                room_id, event_id, thread_id=thread_id
            )
        return await self.client.send_read_receipt(
            room_id, event_id, thread_id=thread_id
        )

    async def set_typing(
        self, room_id: str, typing: bool, timeout_ms: int = 30000
    ) -> dict:
        """Update typing indicator state."""
        return await self.client.set_typing(
            room_id=room_id, typing=typing, timeout=timeout_ms
        )

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
        from ..sender.handlers import send_poll

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
        from ..sender.handlers import send_poll_response

        return await send_poll_response(
            self.client,
            room_id,
            poll_start_event_id,
            answer_ids,
            event_type=event_type,
            poll_key=poll_key,
        )

    async def delete_message(
        self,
        room_id: str,
        event_id: str,
        reason: str | None = None,
        txn_id: str | None = None,
    ) -> dict:
        """Delete (redact) a message in a room."""
        return await self.client.redact_event(
            room_id, event_id, reason=reason, txn_id=txn_id
        )

    async def get_pinned_messages(self, room_id: str) -> list[str]:
        """Get pinned Matrix event IDs in a room."""
        return await self.client.get_room_pinned_events(room_id)

    async def set_pinned_messages(
        self, room_id: str, event_ids
    ) -> dict:
        """Replace pinned Matrix event IDs in a room."""
        return await self.client.set_room_pinned_events(room_id, event_ids)

    async def pin_message(
        self, room_id: str, event_id: str, *, prepend: bool = False
    ) -> dict:
        """Pin a Matrix event in a room."""
        return await self.client.pin_room_event(
            room_id=room_id,
            event_id=event_id,
            prepend=prepend,
        )

    async def unpin_message(self, room_id: str, event_id: str) -> dict:
        """Unpin a Matrix event in a room."""
        return await self.client.unpin_room_event(room_id=room_id, event_id=event_id)

    async def send_with_per_message_profile(
        self,
        room_id: str,
        body: str,
        *,
        displayname: str | None = None,
        avatar_url: str | None = None,
        msgtype: str = "m.text",
        formatted_body: str | None = None,
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
        stable: bool = True,
    ) -> dict | None:
        """
        Send a message with a per-message profile override (MSC4144).

        Bridges and bots often need to render messages under a different
        identity than the sending Matrix user. MSC4144 lets the sender attach
        an alternate ``displayname``/``avatar_url`` to a single event without
        touching the underlying profile.

        Args:
            room_id: Target room ID
            body: Plain-text body
            displayname: Display name to attach to this message
            avatar_url: ``mxc://`` avatar URL to attach to this message
            msgtype: Message type, defaults to ``m.text``
            formatted_body: Optional HTML formatted body
            stable: Also include the stable ``m.per_message_profile`` key
                alongside the unstable ``com.beeper.per_message_profile`` key
        """
        if not displayname and not avatar_url:
            raise ValueError(
                "at least one of displayname/avatar_url is required for per-message profile"
            )
        profile: dict[str, Any] = {}
        if displayname:
            profile["displayname"] = displayname
        if avatar_url:
            profile["avatar_url"] = avatar_url

        content: dict[str, Any] = {
            "msgtype": msgtype,
            "body": body,
            MSC4144_PROFILE_KEY: dict(profile),
        }
        if stable:
            content[M_PROFILE_KEY] = dict(profile)
        if formatted_body:
            content["format"] = "org.matrix.custom.html"
            content["formatted_body"] = formatted_body

        return await self.send_custom_message(
            room_id,
            "m.room.message",
            content,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
        )

    async def send_live_location_beacon_info(
        self,
        room_id: str,
        *,
        description: str | None = None,
        timeout_ms: int = 3600_000,
        live: bool = True,
        asset_type: str = "m.self",
    ) -> dict | None:
        """
        Publish a live-location ``m.beacon_info`` state event (MSC3489).

        The state key MUST be the sender's user ID. Once published, the sender
        can call :meth:`send_live_location_beacon` repeatedly to publish
        ``m.beacon`` events that update the location.
        """
        if timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive for live location")
        user_id = getattr(self.client, "user_id", None)
        if not user_id:
            raise RuntimeError("client.user_id is required for beacon_info")

        ts_ms = int(self._now_ms())
        content: dict[str, Any] = {
            "live": bool(live),
            "timeout": int(timeout_ms),
            "m.ts": ts_ms,
            MSC3488_TS_KEY: ts_ms,
            MSC3488_ASSET_KEY: {"type": asset_type},
            "m.asset": {"type": asset_type},
        }
        if description:
            content["description"] = description

        return await self.client.set_room_state_event(
            room_id=room_id,
            event_type=M_BEACON_INFO,
            content=content,
            state_key=user_id,
        )

    async def send_live_location_beacon(
        self,
        room_id: str,
        beacon_info_event_id: str,
        latitude: float,
        longitude: float,
        *,
        accuracy_m: float | None = None,
        description: str | None = None,
    ) -> dict | None:
        """
        Publish a live-location ``m.beacon`` update (MSC3489).

        Args:
            beacon_info_event_id: The event ID of the ``m.beacon_info`` state event.
            latitude / longitude: Coordinates of the location update.
            accuracy_m: Optional horizontal accuracy in meters.
            description: Optional human-readable description.
        """
        if not beacon_info_event_id:
            raise ValueError("beacon_info_event_id is required")

        geo_uri = f"geo:{latitude},{longitude}"
        if accuracy_m and accuracy_m > 0:
            geo_uri += f";u={accuracy_m}"
        location_payload: dict[str, Any] = {"uri": geo_uri}
        if description:
            location_payload["description"] = description

        ts_ms = int(self._now_ms())
        content: dict[str, Any] = {
            "m.location": location_payload,
            "org.matrix.msc3488.location": dict(location_payload),
            "m.ts": ts_ms,
            MSC3488_TS_KEY: ts_ms,
            "m.relates_to": {
                "rel_type": "m.reference",
                "event_id": beacon_info_event_id,
            },
            MSC1767_TEXT_KEY: description or geo_uri,
        }

        return await self.client.send_room_event(
            room_id=room_id,
            event_type=M_BEACON,
            content=content,
            txn_id=None,
        )

    async def mark_room_unread(
        self, room_id: str, unread: bool = True
    ) -> dict:
        """Mark a room as (un)read for this account (MSC2867)."""
        return await self.client.set_room_marked_unread(room_id, unread)

    async def send_delayed_message(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        delay_ms: int,
        parent_delay_id: str | None = None,
    ) -> dict:
        """Schedule a delayed Matrix event (MSC4140)."""
        return await self.client.send_delayed_room_event(
            room_id=room_id,
            event_type=event_type,
            content=content,
            delay_ms=delay_ms,
            parent_delay_id=parent_delay_id,
        )

    async def cancel_delayed_message(self, delay_id: str) -> dict:
        """Cancel a previously scheduled delayed event (MSC4140)."""
        return await self.client.cancel_delayed_event(delay_id)

    async def fire_delayed_message(self, delay_id: str) -> dict:
        """Immediately fire a pending delayed event (MSC4140)."""
        return await self.client.fire_delayed_event(delay_id)

    async def restart_delayed_message(self, delay_id: str) -> dict:
        """Reset the timeout on a pending delayed event (MSC4140)."""
        return await self.client.restart_delayed_event(delay_id)

    async def list_delayed_messages(
        self, from_token: str | None = None, limit: int | None = None
    ) -> dict:
        """List currently pending delayed events (MSC4140)."""
        return await self.client.list_delayed_events(
            from_token=from_token, limit=limit
        )

    @staticmethod
    def _now_ms() -> int:
        import time

        return int(time.time() * 1000)

"""
Matrix HTTP Client - Message Send Mixin
Provides message sending methods
"""

import json
import os
import secrets
import time
from typing import Any

from astrbot.api import logger

from ...constants import (
    DEFAULT_TIMEOUT_MS_30000,
    M_ROOM_MESSAGE,
    MSC4310_RTC_DECLINE,
    MSC4357_LIVE_MESSAGE_MARKER,
    MSC4446_ALLOW_BACKWARD,
    MSGTYPE_TEXT,
    REL_TYPE_ANNOTATION,
    REL_TYPE_REFERENCE,
    REL_TYPE_REPLACE,
    RESPONSE_TRUNCATE_LENGTH_400,
)
from ..path_utils import quote_path_segment


def _content_has_live_marker(content: dict[str, Any]) -> bool:
    if not isinstance(content, dict):
        return False
    if content.get(MSC4357_LIVE_MESSAGE_MARKER) is not None:
        return True
    new_content = content.get("m.new_content")
    return isinstance(new_content, dict) and (
        new_content.get(MSC4357_LIVE_MESSAGE_MARKER) is not None
    )


def _content_is_edit(content: dict[str, Any]) -> bool:
    if not isinstance(content, dict):
        return False
    relates_to = content.get("m.relates_to")
    return isinstance(relates_to, dict) and relates_to.get("rel_type") == REL_TYPE_REPLACE


def _build_live_message_metadata(
    content: dict[str, Any], *, phase: str | None = None
) -> dict[str, Any] | None:
    if not isinstance(content, dict):
        return None
    if not _content_has_live_marker(content):
        return None
    metadata: dict[str, Any] = {
        "proposal": "msc4357-live-messages",
        "live_message": True,
    }
    if phase:
        metadata["phase"] = phase
    elif _content_is_edit(content):
        metadata["phase"] = "edit"
    else:
        metadata["phase"] = "initial"
    return metadata


class MessageSendMixin:
    """Message sending methods for Matrix client"""

    async def send_message(
        self,
        room_id: str,
        msg_type: str,
        content: dict[str, Any],
        txn_id: str | None = None,
        tracker_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Send a message to a room

        Args:
            room_id: Room ID
            msg_type: Message type (e.g., m.room.message)
            content: Message content

        Returns:
            Send response with event_id
        """
        txn_id = txn_id or f"{int(time.time() * 1000)}_{id(content)}"
        tracker = getattr(self, "outbound_tracker", None)
        runtime_state = getattr(self, "runtime_state", None)
        metadata = _build_live_message_metadata(content)
        if tracker_metadata:
            metadata = {**(metadata or {}), **tracker_metadata}
        if tracker:
            tracker.record_attempt(
                txn_id=txn_id,
                action="send_message",
                room_id=room_id,
                event_type=msg_type,
                content=content,
                metadata=metadata,
            )
        room = quote_path_segment(room_id)
        event_type = quote_path_segment(msg_type)
        txn = quote_path_segment(txn_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/send/{event_type}/{txn}"
        try:
            response = await self._request("PUT", endpoint, data=content)
        except Exception as e:
            if tracker:
                tracker.mark_failure(txn_id, e)
            if runtime_state:
                runtime_state.mark_send_failed(str(e))
            raise
        if tracker:
            tracker.mark_success(txn_id, response)
        if runtime_state:
            runtime_state.mark_send_ok()
            if metadata and metadata.get("live_message"):
                phase = str(metadata.get("phase") or "initial")
                if phase == "initial":
                    runtime_state.mark_live_message_outbound_initial()
                else:
                    runtime_state.mark_live_message_outbound_edit()
        return response

    async def send_room_event(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        txn_id: str | None = None,
        tracker_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Send a custom event to a room

        Args:
            room_id: Room ID
            event_type: Event type (e.g., m.key.verification.request)
            content: Event content

        Returns:
            Send response with event_id
        """
        txn_id = txn_id or f"txn_{int(time.time() * 1000)}"
        tracker = getattr(self, "outbound_tracker", None)
        runtime_state = getattr(self, "runtime_state", None)
        metadata = _build_live_message_metadata(content)
        if tracker_metadata:
            metadata = {**(metadata or {}), **tracker_metadata}
        if tracker:
            tracker.record_attempt(
                txn_id=txn_id,
                action="send_room_event",
                room_id=room_id,
                event_type=event_type,
                content=content,
                metadata=metadata,
            )
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_type)
        txn = quote_path_segment(txn_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/send/{event}/{txn}"
        try:
            response = await self._request("PUT", endpoint, data=content)
        except Exception as e:
            if tracker:
                tracker.mark_failure(txn_id, e)
            if runtime_state:
                runtime_state.mark_send_failed(str(e))
            raise
        if tracker:
            tracker.mark_success(txn_id, response)
        if runtime_state:
            runtime_state.mark_send_ok()
            if metadata and metadata.get("live_message"):
                phase = str(metadata.get("phase") or "edit")
                if phase == "initial":
                    runtime_state.mark_live_message_outbound_initial()
                else:
                    runtime_state.mark_live_message_outbound_edit()
        return response

    async def send_call_decline(
        self,
        room_id: str,
        notification_event_id: str,
        *,
        txn_id: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """
        Send MatrixRTC call decline event (MSC4310).

        Constructs an ``m.rtc.decline`` (unstable type ``org.matrix.msc4310.rtc.decline``)
        event with an ``m.reference`` relation to the declined ``m.rtc.notification`` event.
        Per MSC this event SHOULD NOT include intentional mentions and SHOULD NOT trigger push.

        Args:
            room_id: Room ID
            notification_event_id: Event ID of the ``m.rtc.notification`` being declined
            txn_id: Optional transaction ID
            reason: Optional human-readable decline reason (extension field, not specified by MSC)

        Returns:
            Send response with event_id
        """
        content: dict[str, Any] = {
            "m.relates_to": {
                "rel_type": REL_TYPE_REFERENCE,
                "event_id": notification_event_id,
            },
        }
        if reason:
            content["reason"] = reason
        return await self.send_room_event(
            room_id,
            MSC4310_RTC_DECLINE,
            content,
            txn_id=txn_id,
        )

    async def send_room_message(self, room_id: str, message: str) -> dict[str, Any]:
        """
        Helper to send a simple text message to a room

        Args:
            room_id: Room ID
            message: Message text

        Returns:
            Response data
        """
        return await self.send_message(
            room_id, M_ROOM_MESSAGE, {"msgtype": MSGTYPE_TEXT, "body": message}
        )

    async def edit_message(
        self,
        room_id: str,
        original_event_id: str,
        new_content: dict[str, Any],
        msg_type: str | None = None,
        tracker_metadata: dict[str, Any] | None = None,
        thread_root: str | None = None,
    ) -> dict[str, Any]:
        """
        Edit an existing message

        Args:
            room_id: Room ID
            original_event_id: Event ID of the original message
            new_content: New message content (should include 'body')
            msg_type: Message type. Defaults to ``new_content["msgtype"]`` and
                finally ``m.text`` when the content does not declare one.
            thread_root: When editing a message that lives in a thread, pass
                the thread root event ID so the edit event carries both the
                ``m.replace`` and ``m.thread`` relations (MSC4145). This keeps
                the edit aggregated inside the thread instead of appearing as
                a room-timeline event.

        Returns:
            Send response with event_id
        """
        txn_id = f"{int(time.time() * 1000)}_{id(new_content)}"
        resolved_msg_type = msg_type or new_content.get("msgtype") or MSGTYPE_TEXT
        # Construct edit content according to Matrix spec
        relates_to: dict[str, Any] = {
            "rel_type": REL_TYPE_REPLACE,
            "event_id": original_event_id,
        }
        if thread_root:
            relates_to["m.thread"] = {"event_id": thread_root}
        content = {
            "msgtype": resolved_msg_type,
            "body": f"* {new_content.get('body', '')}",  # Fallback for clients that don't support edits
            "m.new_content": {
                "msgtype": resolved_msg_type,
                "body": new_content.get("body", ""),
                **{
                    k: v for k, v in new_content.items() if k not in ["body", "msgtype"]
                },
            },
            "m.relates_to": relates_to,
        }
        return await self.send_room_event(
            room_id=room_id,
            event_type=M_ROOM_MESSAGE,
            content=content,
            txn_id=txn_id,
            tracker_metadata=tracker_metadata,
        )

    async def send_reaction(
        self, room_id: str, event_id: str, emoji: str
    ) -> dict[str, Any]:
        """
        Send a reaction to an event

        According to Matrix spec, reactions use the m.reaction event type
        with m.relates_to containing rel_type: m.annotation

        Args:
            room_id: Room ID
            event_id: Event ID to react to
            emoji: The emoji to react with (e.g., "👍", "❤️")

        Returns:
            Response with event_id of the reaction
        """
        txn_id = f"{int(time.time() * 1000)}_{id(emoji)}"
        room = quote_path_segment(room_id)
        txn = quote_path_segment(txn_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/send/m.reaction/{txn}"

        content = {
            "m.relates_to": {
                "rel_type": REL_TYPE_ANNOTATION,
                "event_id": event_id,
                "key": emoji,
            }
        }

        return await self._request("PUT", endpoint, data=content)

    async def send_to_device(
        self, event_type: str, messages: dict[str, Any], txn_id: str | None = None
    ) -> dict[str, Any]:
        """
        Send to-device events to specific devices

        Args:
            event_type: The type of event to send
            messages: Dict of user_id -> device_id -> content or Dict of user_id -> content
            txn_id: Transaction ID (auto-generated if not provided)

        Returns:
            Empty dict on success
        """
        if txn_id is None:
            txn_id = secrets.token_hex(16)

        event = quote_path_segment(event_type)
        txn = quote_path_segment(txn_id)
        endpoint = f"/_matrix/client/v3/sendToDevice/{event}/{txn}"

        # Handle different message formats
        if isinstance(messages, dict):
            # Already {"messages": ...} structure
            if "messages" in messages:
                data = messages
            else:
                # Check if user_id -> device_id -> content (device map)
                is_device_map = True
                for value in messages.values():
                    if not isinstance(value, dict):
                        is_device_map = False
                        break
                    if value and not all(isinstance(v, dict) for v in value.values()):
                        is_device_map = False
                        break

                if is_device_map:
                    data = {"messages": messages}
                else:
                    # Treat as user_id -> content, map to all devices
                    normalized = {
                        user: {"*": content} for user, content in messages.items()
                    }
                    data = {"messages": normalized}
        else:
            data = {"messages": messages}

        # Control verbose logging via environment variable to avoid accidental secret leaks
        verbose_env = os.environ.get("ASTRBOT_VERBOSE_TO_DEVICE", "").lower()
        verbose = verbose_env in ("1", "true", "yes")

        # Helper to produce a short, safe representation of potentially large dicts
        def _short(obj: Any, maxlen: int = RESPONSE_TRUNCATE_LENGTH_400) -> str:
            try:
                s = json.dumps(obj, ensure_ascii=False)
            except Exception:
                s = str(obj)
            if len(s) > maxlen:
                return s[: maxlen - 80] + f"... (truncated, {len(s)} bytes)"
            return s

        try:
            response = await self._request("PUT", endpoint, data=data)
        except Exception as e:
            logger.error(
                f"send_to_device failed for {event_type} txn {txn_id}: {e}"
            )
            raise
        try:
            logger.debug(
                f"send_to_device response for {event_type} txn {txn_id}: body={_short(response)}"
            )
            if verbose:
                logger.debug(
                    f"send_to_device request payload: {_short(data, maxlen=2000)}"
                )
                logger.debug(
                    f"send_to_device full response: {_short(response, maxlen=2000)}"
                )
        except Exception:
            pass
        return response
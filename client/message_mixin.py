"""
Matrix HTTP Client - Message Mixin
Provides message sending and manipulation methods
"""

import json
import os
import secrets
import time
from typing import Any

import aiohttp

from astrbot.api import logger

from ..constants import (
    DEFAULT_TIMEOUT_MS_30000,
    HTTP_ERROR_STATUS_400,
    RESPONSE_TRUNCATE_LENGTH_400,
)


class MessageMixin:
    """Message-related methods for Matrix client"""

    async def send_message(
        self, room_id: str, msg_type: str, content: dict[str, Any]
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
        txn_id = f"{int(time.time() * 1000)}_{id(content)}"
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/send/{msg_type}/{txn_id}"
        return await self._request("PUT", endpoint, data=content)

    async def send_room_event(
        self, room_id: str, event_type: str, content: dict[str, Any]
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
        txn_id = f"txn_{int(time.time() * 1000)}"
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}"
        return await self._request("PUT", endpoint, data=content)

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
            room_id, "m.room.message", {"msgtype": "m.text", "body": message}
        )

    async def edit_message(
        self,
        room_id: str,
        original_event_id: str,
        new_content: dict[str, Any],
        msg_type: str = "m.text",
    ) -> dict[str, Any]:
        """
        Edit an existing message

        Args:
            room_id: Room ID
            original_event_id: Event ID of the original message
            new_content: New message content (should include 'body')
            msg_type: Message type (default: m.text)

        Returns:
            Send response with event_id
        """
        txn_id = f"{int(time.time() * 1000)}_{id(new_content)}"
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn_id}"

        # Construct edit content according to Matrix spec
        content = {
            "msgtype": msg_type,
            "body": f"* {new_content.get('body', '')}",  # Fallback for clients that don't support edits
            "m.new_content": {
                "msgtype": msg_type,
                "body": new_content.get("body", ""),
                **{
                    k: v for k, v in new_content.items() if k not in ["body", "msgtype"]
                },
            },
            "m.relates_to": {"rel_type": "m.replace", "event_id": original_event_id},
        }

        return await self._request("PUT", endpoint, data=content)

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
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/send/m.reaction/{txn_id}"

        content = {
            "m.relates_to": {
                "rel_type": "m.annotation",
                "event_id": event_id,
                "key": emoji,
            }
        }

        return await self._request("PUT", endpoint, data=content)

    async def send_read_receipt(self, room_id: str, event_id: str) -> dict[str, Any]:
        """
        Send read receipt for an event

        Args:
            room_id: Room ID
            event_id: Event ID to acknowledge

        Returns:
            Response data
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/receipt/m.read/{event_id}"
        return await self._request("POST", endpoint, data={})

    async def send_read_receipt_private(
        self, room_id: str, event_id: str
    ) -> dict[str, Any]:
        """
        Send private read receipt for an event

        Args:
            room_id: Room ID
            event_id: Event ID to acknowledge

        Returns:
            Response data
        """
        endpoint = (
            f"/_matrix/client/v3/rooms/{room_id}/receipt/m.read.private/{event_id}"
        )
        return await self._request("POST", endpoint, data={})

    async def send_read_markers(
        self,
        room_id: str,
        fully_read: str | None = None,
        read: str | None = None,
    ) -> dict[str, Any]:
        """
        Set read markers for a room

        Args:
            room_id: Room ID
            fully_read: Event ID for fully_read marker
            read: Event ID for read marker

        Returns:
            Response data
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/read_markers"
        data: dict[str, Any] = {}
        if fully_read:
            data["m.fully_read"] = fully_read
        if read:
            data["m.read"] = read
        return await self._request("POST", endpoint, data=data)

    async def redact_event(
        self,
        room_id: str,
        event_id: str,
        reason: str | None = None,
        txn_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Redact an event

        Args:
            room_id: Room ID
            event_id: Event ID to redact
            reason: Optional reason
            txn_id: Optional transaction ID

        Returns:
            Response with event_id
        """
        if txn_id is None:
            txn_id = f"redact_{int(time.time() * 1000)}"
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}"
        data: dict[str, Any] = {}
        if reason:
            data["reason"] = reason
        return await self._request("PUT", endpoint, data=data)

    async def report_event(
        self, room_id: str, event_id: str, score: int = 0, reason: str | None = None
    ) -> dict[str, Any]:
        """
        Report an event

        Args:
            room_id: Room ID
            event_id: Event ID to report
            score: Negative score for abuse (-100..0)
            reason: Optional reason

        Returns:
            Response data
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/report/{event_id}"
        data: dict[str, Any] = {"score": score}
        if reason:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)

    async def get_event_context(
        self,
        room_id: str,
        event_id: str,
        limit: int | None = None,
        filter: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Get context around an event

        Args:
            room_id: Room ID
            event_id: Event ID
            limit: Optional limit
            filter: Optional filter

        Returns:
            Context response
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/context/{event_id}"
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if filter is not None:
            params["filter"] = json.dumps(filter, ensure_ascii=False)
        return await self._request("GET", endpoint, params=params)

    async def get_event_relations(
        self,
        room_id: str,
        event_id: str,
        rel_type: str,
        event_type: str | None = None,
        from_token: str | None = None,
        to_token: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """
        Get relations for an event

        Args:
            room_id: Room ID
            event_id: Event ID
            rel_type: Relation type (e.g., m.annotation)
            event_type: Optional event type filter
            from_token: Pagination token
            to_token: Pagination token
            limit: Optional limit

        Returns:
            Relations response
        """
        path = f"/_matrix/client/v3/rooms/{room_id}/relations/{event_id}/{rel_type}"
        if event_type:
            path += f"/{event_type}"
        params: dict[str, Any] = {}
        if from_token:
            params["from"] = from_token
        if to_token:
            params["to"] = to_token
        if limit is not None:
            params["limit"] = limit
        return await self._request("GET", path, params=params)

    async def set_typing(
        self, room_id: str, typing: bool = True, timeout: int = DEFAULT_TIMEOUT_MS_30000
    ) -> dict[str, Any]:
        """
        Set typing status in a room

        Args:
            room_id: Room ID
            typing: Whether the user is typing
            timeout: Typing timeout in milliseconds

        Returns:
            Response data
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/typing/{self.user_id}"
        data = {"typing": typing, "timeout": timeout} if typing else {"typing": False}
        return await self._request("PUT", endpoint, data=data)

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

        endpoint = f"/_matrix/client/v3/sendToDevice/{event_type}/{txn_id}"

        # 处理不同的消息格式
        if isinstance(messages, dict):
            # 已经是 {"messages": ...} 的结构
            if "messages" in messages:
                data = messages
            else:
                # 判断是否是 user_id -> device_id -> content（设备映射）
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
                    # 视为 user_id -> content，映射到所有设备
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

        # Build request manually so we can capture HTTP status and raw response body
        await self._ensure_session()
        url = f"{self.homeserver}{endpoint}"
        headers = self._get_headers()

        try:
            async with self.session.put(url, json=data, headers=headers) as resp:
                status = resp.status
                # Try to parse JSON, fallback to text
                try:
                    resp_body = await resp.json()
                except Exception:
                    resp_text = await resp.text()
                    resp_body = resp_text

                # Log summary for diagnostics
                try:
                    logger.debug(
                        f"send_to_device response for {event_type} txn {txn_id}: status={status} body={_short(resp_body)}"
                    )

                    if verbose:
                        logger.debug(
                            f"send_to_device request payload: {_short(data, maxlen=2000)}"
                        )
                        logger.debug(
                            f"send_to_device full response: {_short(resp_body, maxlen=2000)}"
                        )
                except Exception:
                    pass

                if status >= HTTP_ERROR_STATUS_400:
                    # Try to extract errcode/message if JSON
                    if isinstance(resp_body, dict):
                        error_code = resp_body.get("errcode", "UNKNOWN")
                        error_msg = resp_body.get("error", "Unknown error")
                    else:
                        error_code = "UNKNOWN"
                        error_msg = str(resp_body)

                    raise Exception(
                        f"Matrix API error: {error_code} - {error_msg} (status: {status})"
                    )

                return resp_body

        except aiohttp.ClientError as e:
            logger.error(
                f"send_to_device network error for {event_type} txn {txn_id}: {e}"
            )
            raise

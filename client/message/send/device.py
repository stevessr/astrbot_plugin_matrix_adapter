"""Matrix to-device event send operations."""

import json
import os
import secrets
from typing import Any

from astrbot.api import logger

from ....constants import RESPONSE_TRUNCATE_LENGTH_400
from ...path_utils import quote_path_segment


class MessageToDeviceMixin:
    """Send events directly to Matrix devices."""

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
            logger.error(f"send_to_device failed for {event_type} txn {txn_id}: {e}")
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


__all__ = ["MessageToDeviceMixin"]

"""Message content dispatch (polls, beacons, msgtype handlers)."""

from ......constants import (
    M_POLL_END,
    M_POLL_RESPONSE,
    M_POLL_START,
    MSC3381_POLL_END,
    MSC3381_POLL_RESPONSE,
    MSC3381_POLL_START,
    MSGTYPE_TEXT,
)
from .....events import (
    BEACON_EVENT_TYPES,
    handle_beacon,
    handle_beacon_info,
    handle_extensible_event,
    handle_poll_end,
    handle_poll_response,
    handle_poll_start,
    handle_unknown,
)
from ..helpers import _has_extensible_content


class MatrixReceiverMessageContentMixin:
    """Dispatch message content into the AstrBot message chain."""

    async def _append_message_content(self, chain, event, msgtype, event_type):
        # Handle poll events by event type rather than msgtype
        if event_type in (M_POLL_START, MSC3381_POLL_START):
            await handle_poll_start(self, chain, event, event_type)
        elif event_type in (M_POLL_RESPONSE, MSC3381_POLL_RESPONSE):
            await handle_poll_response(self, chain, event, event_type)
        elif event_type in (M_POLL_END, MSC3381_POLL_END):
            await handle_poll_end(self, chain, event, event_type)
        elif (
            event_type in BEACON_EVENT_TYPES
            and event_type
            and "beacon_info" in event_type
        ):
            await handle_beacon_info(self, chain, event, event_type)
        elif event_type in BEACON_EVENT_TYPES:
            await handle_beacon(self, chain, event, event_type)
        else:
            handler = self._MSGTYPE_HANDLERS.get(msgtype)
            if handler is not None:
                await handler(self, chain, event, msgtype)
            elif msgtype or not _has_extensible_content(event.content):
                await handle_unknown(self, chain, event, msgtype or "")
            else:
                await handle_extensible_event(self, chain, event, MSGTYPE_TEXT)

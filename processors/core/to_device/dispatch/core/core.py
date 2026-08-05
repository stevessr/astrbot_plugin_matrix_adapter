"""Matrix to-device event processing orchestration."""

from astrbot.api import logger

from .dispatch import _dispatch_to_device_event
from .request import _collect_cancelled_requests
from .sort import _sort_to_device_events
from .verify import _handle_secret_request, _handle_verification_to_device


class MatrixEventProcessorToDeviceCoreMixin:
    """Handle encrypted room-key, verification, and secret events."""

    async def process_to_device_events(self, events: list):
        """
        Process to-device events

        Args:
            events: List of to-device events
        """
        if events:
            logger.debug(f"收到 {len(events)} 个 to_device 事件")

        # Import available room keys before answering sibling-device requests,
        # then handle those requests before unrelated verification traffic.
        cancelled_requests = _collect_cancelled_requests(events)
        events = _sort_to_device_events(events)

        for event in events:
            await _dispatch_to_device_event(self, event, cancelled_requests)


# Preserve direct method attributes exposed by the former core mixin.
for _method in (
    _collect_cancelled_requests,
    _dispatch_to_device_event,
    _handle_secret_request,
    _handle_verification_to_device,
    _sort_to_device_events,
):
    setattr(MatrixEventProcessorToDeviceCoreMixin, _method.__name__, _method)

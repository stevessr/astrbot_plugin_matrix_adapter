"""Processor lifecycle state, callbacks, and message deduplication."""

from collections import OrderedDict
from collections.abc import Callable
from typing import TYPE_CHECKING

from ...config.plugin import get_plugin_config
from ...constants import MAX_PROCESSED_MESSAGES_1000
from ...utils import parse_bool

if TYPE_CHECKING:
    from ...e2ee import E2EEManager


class MatrixEventProcessorStateMixin:
    """Initialize processor state and maintain processed-message bounds."""

    def __init__(
        self,
        client,
        user_id: str,
        startup_ts: int,
        call_event_config=None,
    ):
        """
        Initialize event processor

        Args:
            client: Matrix HTTP client
            user_id: Bot's user ID
            startup_ts: Startup timestamp (milliseconds) for filtering historical messages
            call_event_config: Optional CallEventConfig controlling whether VoIP /
                MatrixRTC (live) call events are surfaced as system messages
        """
        self.client = client
        self.user_id = user_id
        self.startup_ts = startup_ts
        self.call_event_config = call_event_config
        self.storage_backend_config = get_plugin_config().storage_backend_config

        # Message deduplication
        self._processed_messages: OrderedDict[str, None] = OrderedDict()
        self._max_processed_messages = MAX_PROCESSED_MESSAGES_1000

        # Matrix v1.16 clarification: when multiple m.replace revisions are
        # observed for the same target, only the newest revision is current.
        # Keep a bounded ordering cache so a delayed /sync or history fill
        # cannot make an older edit supersede a newer one already delivered.
        self._latest_replacements: OrderedDict[
            tuple[str, str], tuple[int, str]
        ] = OrderedDict()

        # Event callbacks
        self.on_message: Callable | None = None

        # E2EE manager (set by adapter if E2EE is enabled)
        self.e2ee_manager: E2EEManager | None = None

        # Sync stream caches
        self.global_account_data: dict[str, dict] = {}
        self.room_account_data: dict[str, dict[str, dict]] = {}
        self.presence: dict[str, dict] = {}
        self.typing: dict[str, set[str]] = {}
        self.receipts: dict[str, dict] = {}
        self.device_lists: dict[str, set[str]] = {"changed": set(), "left": set()}
        self.one_time_keys_count: dict[str, int] = {}
        self.unused_fallback_key_types: list[str] | None = None
        self._init_member_storage()

    def set_message_callback(self, callback: Callable):
        """
        Set callback for processed messages

        Args:
            callback: Async function(room, event) -> None
        """
        self.on_message = callback

    def _is_message_processed(self, event_id: str | None) -> bool:
        if not event_id:
            return False
        return event_id in self._processed_messages

    def _mark_message_processed(self, event_id: str | None) -> None:
        if not event_id:
            return
        self._processed_messages[event_id] = None
        self._processed_messages.move_to_end(event_id, last=True)
        while len(self._processed_messages) > self._max_processed_messages:
            self._processed_messages.popitem(last=False)

    _parse_bool_like = staticmethod(parse_bool)

    def clear_processed_messages(self):
        """Clear the processed messages and replacement-order caches."""
        self._processed_messages.clear()
        self._latest_replacements.clear()

    def get_processed_message_count(self) -> int:
        """Get the number of processed messages in cache"""
        return len(self._processed_messages)

"""Typed service bundle for one Matrix adapter instance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...auth.auth import MatrixAuth
    from ...client import MatrixHTTPClient
    from ...e2ee import E2EEManager
    from ...processors.core import MatrixEventProcessor
    from ...processors.event_handler import MatrixEventHandler
    from ...receiver.core import MatrixReceiver
    from ...sender.core import MatrixSender
    from ...sticker import StickerAvailabilityStore, StickerPackSyncer, StickerStorage
    from ...storage.stores.outbound import MatrixOutboundTracker
    from ...sync.core import MatrixSyncManager
    from ..state import MatrixRuntimeState


@dataclass(slots=True)
class MatrixAdapterServices:
    """Runtime services owned by one Matrix platform instance."""

    client: MatrixHTTPClient
    runtime_state: MatrixRuntimeState
    storage_dir: str
    outbound_tracker: MatrixOutboundTracker
    auth: MatrixAuth
    sender: MatrixSender
    receiver: MatrixReceiver
    event_handler: MatrixEventHandler
    sync_manager: MatrixSyncManager
    event_processor: MatrixEventProcessor
    e2ee_manager: E2EEManager | None
    sticker_available: StickerAvailabilityStore
    sticker_storage: StickerStorage
    sticker_syncer: StickerPackSyncer
    max_upload_size: int

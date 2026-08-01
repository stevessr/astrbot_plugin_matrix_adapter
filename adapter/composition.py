"""Composition root for Matrix adapter services.

The platform boundary should expose lifecycle operations, not construct every
transport, storage, and event-processing implementation itself.  This module
owns that wiring and returns one typed service bundle to the platform class.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from astrbot.api import logger

from ..auth.auth import MatrixAuth
from ..client import MatrixHTTPClient
from ..config.matrix import MatrixConfig
from ..constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES

if TYPE_CHECKING:
    from ..e2ee import E2EEManager
from ..processors.core import MatrixEventProcessor
from ..processors.event_handler import MatrixEventHandler
from ..receiver.core import MatrixReceiver
from ..sender.core import MatrixSender
from ..sticker import StickerAvailabilityStore, StickerPackSyncer, StickerStorage
from ..storage.paths import MatrixStoragePaths
from ..storage.stores.outbound import MatrixOutboundTracker
from ..sync.core import MatrixSyncManager
from ..utils.utils import MatrixUtils
from .state import MatrixRuntimeState


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


async def _noop_token_invalid() -> bool:
    return False


def build_adapter_services(
    *,
    platform_config: dict[str, Any],
    matrix_config: MatrixConfig,
    startup_ts: int,
    on_token_invalid: Callable[[], Awaitable[bool]] = _noop_token_invalid,
    on_sync_response: Callable[[dict], Awaitable[None]] | None = None,
    message_callback: Callable[..., Awaitable[None]] | None = None,
) -> MatrixAdapterServices:
    """Construct and wire all services for one Matrix adapter instance.

    This is the only composition point for the platform runtime.  Individual
    services retain their focused interfaces and do not need to know how the
    AstrBot platform assembled them.
    """

    client = MatrixHTTPClient(homeserver=matrix_config.homeserver)
    runtime_state = MatrixRuntimeState()
    client.runtime_state = runtime_state

    if not matrix_config.user_id:
        raise ValueError("user_id is required for storage initialization")

    user_storage_dir = MatrixStoragePaths.get_user_storage_dir(
        matrix_config.store_path,
        matrix_config.homeserver,
        matrix_config.user_id,
    )
    MatrixStoragePaths.ensure_directory(user_storage_dir, treat_as_file=False)

    storage_backend_config = getattr(matrix_config, "storage_backend_config", None)
    backend = storage_backend_config.backend if storage_backend_config else "json"
    pgsql_dsn = storage_backend_config.pgsql_dsn if storage_backend_config else ""
    pgsql_schema = (
        storage_backend_config.pgsql_schema if storage_backend_config else "public"
    )
    pgsql_table_prefix = (
        storage_backend_config.pgsql_table_prefix
        if storage_backend_config
        else "matrix_store"
    )

    outbound_tracker = MatrixOutboundTracker(
        user_storage_dir=user_storage_dir,
        store_path=matrix_config.store_path,
        backend=backend,
        pgsql_dsn=pgsql_dsn,
        pgsql_schema=pgsql_schema,
        pgsql_table_prefix=pgsql_table_prefix,
    )
    client.outbound_tracker = outbound_tracker

    auth = MatrixAuth(client, matrix_config, token_store_path=None)
    sender = MatrixSender(client, use_notice=matrix_config.use_notice)

    bot_name = platform_config.get("matrix_bot_name", matrix_config.device_name)
    receiver = MatrixReceiver(
        matrix_config.user_id,
        lambda mxc: MatrixUtils.mxc_to_http(mxc, matrix_config.homeserver),
        bot_name=bot_name,
        client=client,
    )
    event_handler = MatrixEventHandler(client, matrix_config.auto_join_rooms)
    sync_manager = MatrixSyncManager(
        client=client,
        sync_timeout=matrix_config.sync_timeout,
        auto_join_rooms=matrix_config.auto_join_rooms,
        homeserver=matrix_config.homeserver,
        user_id=matrix_config.user_id,
        store_path=matrix_config.store_path,
        on_token_invalid=on_token_invalid,
    )
    event_processor = MatrixEventProcessor(
        client=client,
        user_id=matrix_config.user_id,
        startup_ts=startup_ts,
        call_event_config=matrix_config.call_event_config,
    )

    e2ee_manager: E2EEManager | None = None
    if matrix_config.enable_e2ee:
        from ..e2ee import VODOZEMAC_AVAILABLE, E2EEManager

        if VODOZEMAC_AVAILABLE:
            recovery_key = matrix_config.e2ee_recovery_key
            if recovery_key:
                logger.info("检测到已配置的恢复密钥")
            else:
                logger.warning("未配置恢复密钥 (matrix_e2ee_recovery_key)")

            e2ee_manager = E2EEManager(
                client=client,
                user_id=matrix_config.user_id,
                device_id=client.device_id or matrix_config.device_id,
                store_path=matrix_config.e2ee_store_path,
                homeserver=matrix_config.homeserver,
                auto_verify_mode=matrix_config.e2ee_auto_verify,
                enable_key_backup=matrix_config.e2ee_key_backup,
                recovery_key=recovery_key,
                trust_on_first_use=matrix_config.e2ee_trust_on_first_use,
                password=matrix_config.password,
                proactive_key_exchange=matrix_config.e2ee_proactive_key_exchange,
                key_maintenance_interval=matrix_config.e2ee_key_maintenance_interval,
                otk_threshold_ratio=matrix_config.e2ee_otk_threshold_ratio,
                key_share_check_interval=matrix_config.e2ee_key_share_check_interval,
            )
            event_processor.e2ee_manager = e2ee_manager
            sender.e2ee_manager = e2ee_manager
        else:
            logger.warning(
                "E2EE 已启用但 vodozemac 未安装。请运行：pip install vodozemac"
            )

    sync_manager.set_room_event_callback(event_processor.process_room_events)
    sync_manager.set_to_device_event_callback(event_processor.process_to_device_events)
    sync_manager.set_invite_callback(event_handler.invite_callback)
    sync_manager.set_knock_callback(event_handler.knock_callback)
    sync_manager.set_leave_callback(event_processor.process_leave_events)
    sync_manager.set_ephemeral_callback(event_processor.process_ephemeral_events)
    sync_manager.set_room_account_data_callback(
        event_processor.process_room_account_data_events
    )
    sync_manager.set_account_data_callback(event_processor.process_account_data_events)
    sync_manager.set_presence_callback(event_processor.process_presence_events)
    sync_manager.set_device_lists_callback(event_processor.process_device_lists)
    sync_manager.set_device_one_time_keys_count_callback(
        event_processor.process_device_one_time_keys_count
    )
    if on_sync_response is not None:
        sync_manager.on_sync = on_sync_response
    if message_callback is not None:
        event_processor.set_message_callback(message_callback)

    available_path = Path(user_storage_dir) / "sticker_available.json"
    sticker_available = StickerAvailabilityStore(available_path)
    sticker_storage = StickerStorage(availability_store=sticker_available)
    sticker_syncer = StickerPackSyncer(
        storage=sticker_storage,
        client=client,
        availability_store=sticker_available,
    )

    return MatrixAdapterServices(
        client=client,
        runtime_state=runtime_state,
        storage_dir=str(user_storage_dir),
        outbound_tracker=outbound_tracker,
        auth=auth,
        sender=sender,
        receiver=receiver,
        event_handler=event_handler,
        sync_manager=sync_manager,
        event_processor=event_processor,
        e2ee_manager=e2ee_manager,
        sticker_available=sticker_available,
        sticker_storage=sticker_storage,
        sticker_syncer=sticker_syncer,
        max_upload_size=DEFAULT_MAX_UPLOAD_SIZE_BYTES,
    )


__all__ = ["MatrixAdapterServices", "build_adapter_services"]

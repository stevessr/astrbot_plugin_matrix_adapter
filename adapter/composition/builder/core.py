"""Construct and wire Matrix adapter services."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ....auth.auth import MatrixAuth
from ....client import MatrixHTTPClient
from ....config.matrix import MatrixConfig
from ....constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES
from ....processors.core import MatrixEventProcessor
from ....processors.event_handler import MatrixEventHandler
from ....receiver.core import MatrixReceiver
from ....sender.core import MatrixSender
from ....sync.core import MatrixSyncManager
from ....utils.utils import MatrixUtils
from ...state import MatrixRuntimeState
from ..services import MatrixAdapterServices
from .e2ee import _init_e2ee_manager
from .stickers import _init_sticker_services
from .storage import _init_storage
from .wire import _wire_callbacks


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

    user_storage_dir, outbound_tracker = _init_storage(matrix_config)
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

    e2ee_manager = _init_e2ee_manager(matrix_config, client, event_processor, sender)

    _wire_callbacks(
        sync_manager,
        event_processor,
        event_handler,
        on_sync_response,
        message_callback,
    )

    sticker_available, sticker_storage, sticker_syncer = _init_sticker_services(
        user_storage_dir, client
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

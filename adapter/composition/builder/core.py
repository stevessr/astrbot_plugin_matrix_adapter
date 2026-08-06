"""Construct and wire Matrix adapter services."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ....config.matrix import MatrixConfig
from ....constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES
from ..services import MatrixAdapterServices
from .client import _build_adapter_client
from .components import _build_adapter_components
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

    client, runtime_state = _build_adapter_client(matrix_config)

    user_storage_dir, outbound_tracker = _init_storage(matrix_config)
    client.outbound_tracker = outbound_tracker

    components = _build_adapter_components(
        matrix_config=matrix_config,
        platform_config=platform_config,
        client=client,
        startup_ts=startup_ts,
        on_token_invalid=on_token_invalid,
        user_storage_dir=user_storage_dir,
    )

    e2ee_manager = _init_e2ee_manager(
        matrix_config,
        client,
        components["event_processor"],
        components["sender"],
    )

    _wire_callbacks(
        components["sync_manager"],
        components["event_processor"],
        components["event_handler"],
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
        auth=components["auth"],
        sender=components["sender"],
        receiver=components["receiver"],
        event_handler=components["event_handler"],
        sync_manager=components["sync_manager"],
        event_processor=components["event_processor"],
        e2ee_manager=e2ee_manager,
        sticker_available=sticker_available,
        sticker_storage=sticker_storage,
        sticker_syncer=sticker_syncer,
        max_upload_size=DEFAULT_MAX_UPLOAD_SIZE_BYTES,
    )

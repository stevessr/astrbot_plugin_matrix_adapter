"""Adapter service component construction."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ....auth.auth import MatrixAuth
from ....client import MatrixHTTPClient
from ....config.matrix import MatrixConfig
from ....processors.core import MatrixEventProcessor
from ....processors.event_handler import MatrixEventHandler
from ....receiver.core import MatrixReceiver
from ....sender.core import MatrixSender
from ....sync.core import MatrixSyncManager
from ....utils.utils import MatrixUtils


def _build_adapter_components(
    *,
    matrix_config: MatrixConfig,
    platform_config: dict[str, Any],
    client: MatrixHTTPClient,
    startup_ts: int,
    on_token_invalid: Callable[[], Awaitable[bool]],
    user_storage_dir,
) -> dict:
    """Construct auth, sender, receiver, and processing components."""
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

    return {
        "auth": auth,
        "sender": sender,
        "receiver": receiver,
        "event_handler": event_handler,
        "sync_manager": sync_manager,
        "event_processor": event_processor,
        "user_storage_dir": user_storage_dir,
    }


__all__ = ["_build_adapter_components"]

"""Megolm outbound session rotation checks."""

import time

from ....constants import (
    DEFAULT_MEGOLM_ROTATION_PERIOD_MS,
    DEFAULT_MEGOLM_ROTATION_PERIOD_MSGS,
)


class E2EEManagerSessionEncryptMessageRotationMixin:
    """按旋转周期与共享历史校验并轮换出站会话。"""

    async def _check_outbound_session_rotation(
        self,
        room_id: str,
        session_info,
        shared_history,
    ):
        if session_info:
            session_id = session_info[0]
            get_outbound_metadata = getattr(
                self._store,
                "get_megolm_outbound_metadata",
                None,
            )
            metadata = (
                get_outbound_metadata(room_id)
                if callable(get_outbound_metadata)
                else None
            )
            configs = getattr(self, "_room_encryption_config", {})
            encryption_config = (
                configs.get(room_id) if isinstance(configs, dict) else None
            )
            if not isinstance(encryption_config, dict):
                encryption_config = {}
            configured_period_ms = encryption_config.get("rotation_period_ms")
            configured_period_msgs = encryption_config.get("rotation_period_msgs")
            rotation_period_ms = (
                configured_period_ms
                if type(configured_period_ms) is int and configured_period_ms >= 0
                else DEFAULT_MEGOLM_ROTATION_PERIOD_MS
            )
            rotation_period_msgs = (
                configured_period_msgs
                if type(configured_period_msgs) is int and configured_period_msgs >= 0
                else DEFAULT_MEGOLM_ROTATION_PERIOD_MSGS
            )
            created_at_ms = (
                metadata.get("created_at_ms")
                if isinstance(metadata, dict)
                and metadata.get("session_id") == session_id
                else None
            )
            message_count = (
                metadata.get("message_count")
                if isinstance(metadata, dict)
                and metadata.get("session_id") == session_id
                else None
            )
            rotation_due = (
                type(created_at_ms) is not int
                or type(message_count) is not int
                or int(time.time() * 1000) - created_at_ms >= rotation_period_ms
                or message_count >= rotation_period_msgs
            )
            if rotation_due and self._discard_outbound_session(room_id):
                session_info = None

        if session_info:
            metadata_getter = getattr(
                self._olm,
                "get_megolm_outbound_shared_history",
                None,
            )
            session_shared_history = (
                metadata_getter(room_id) if callable(metadata_getter) else None
            )
            # Legacy sessions have no MSC4268 metadata. Rotate them rather
            # than incorrectly claiming that their history is shareable.
            if session_shared_history is None or (
                session_shared_history != shared_history
            ):
                if self._discard_outbound_session(room_id):
                    session_info = None

        return session_info

"""Composable CryptoStore queue, record, lifecycle, and loading persistence helpers."""

import copy
from concurrent.futures import Future, wait
from pathlib import Path
from typing import Any

from astrbot.api import logger

from .compat import CryptoStorePersistCompatibilityMixin
from .lifecycle import CryptoStorePersistLifecycleMixin
from .loading import CryptoStorePersistLoadingMixin
from .queue import CryptoStorePersistQueueMixin
from .records import CryptoStorePersistRecordsMixin


class CryptoStorePersistMixin(
    CryptoStorePersistCompatibilityMixin,
    CryptoStorePersistQueueMixin,
    CryptoStorePersistRecordsMixin,
    CryptoStorePersistLifecycleMixin,
    CryptoStorePersistLoadingMixin,
):
    """Persistence layer split by queue, records, lifecycle, and loading concerns."""

    _RECORD_ACCOUNT = "olm_account"
    _RECORD_SESSIONS = "olm_sessions"
    _RECORD_MEGOLM_INBOUND = "megolm_inbound"
    _RECORD_MEGOLM_INBOUND_META = "megolm_inbound_meta"
    _RECORD_MEGOLM_REPLAY = "megolm_replay"
    _RECORD_MEGOLM_OUTBOUND = "megolm_outbound"
    _RECORD_MEGOLM_OUTBOUND_META = "megolm_outbound_meta"
    _RECORD_DEVICE_KEYS = "device_keys"
    _RECORD_STORED_DEVICE_ID = "stored_device_id"
    _PERSIST_QUEUE_WAIT_TIMEOUT_SECONDS = 15.0
    _PERSIST_FLUSH_TIMEOUT_SECONDS = 10.0
    _LEGACY_FILES = {
        _RECORD_ACCOUNT: "olm_account.json",
        _RECORD_SESSIONS: "olm_sessions.json",
        _RECORD_MEGOLM_INBOUND: "megolm_inbound.json",
        _RECORD_MEGOLM_INBOUND_META: "megolm_inbound_meta.json",
        _RECORD_MEGOLM_REPLAY: "megolm_replay.json",
        _RECORD_MEGOLM_OUTBOUND: "megolm_outbound.json",
        _RECORD_MEGOLM_OUTBOUND_META: "megolm_outbound_meta.json",
        _RECORD_DEVICE_KEYS: "device_keys.json",
        _RECORD_STORED_DEVICE_ID: "stored_device_id.json",
    }


# Preserve direct method and descriptor attributes exposed by the former mixin.
CryptoStorePersistMixin._json_filename_resolver = classmethod(
    CryptoStorePersistCompatibilityMixin.__dict__["_json_filename_resolver"].__func__
)
CryptoStorePersistMixin._legacy_path_for_record = (
    CryptoStorePersistRecordsMixin._legacy_path_for_record
)
CryptoStorePersistMixin._clone_record_data = staticmethod(
    CryptoStorePersistRecordsMixin._clone_record_data
)
CryptoStorePersistMixin._redact_device_id = staticmethod(
    CryptoStorePersistRecordsMixin._redact_device_id
)
CryptoStorePersistMixin._on_persist_future_done = (
    CryptoStorePersistQueueMixin._on_persist_future_done
)
CryptoStorePersistMixin._submit_persist_job = (
    CryptoStorePersistQueueMixin._submit_persist_job
)
CryptoStorePersistMixin.flush = CryptoStorePersistQueueMixin.flush
CryptoStorePersistMixin.close = CryptoStorePersistQueueMixin.close
CryptoStorePersistMixin._read_record = CryptoStorePersistRecordsMixin._read_record
CryptoStorePersistMixin._save_record = CryptoStorePersistRecordsMixin._save_record
CryptoStorePersistMixin._delete_record_sync = (
    CryptoStorePersistRecordsMixin._delete_record_sync
)
CryptoStorePersistMixin._delete_record = CryptoStorePersistRecordsMixin._delete_record
CryptoStorePersistMixin._check_device_id_change = (
    CryptoStorePersistLifecycleMixin._check_device_id_change
)
CryptoStorePersistMixin._save_device_id = (
    CryptoStorePersistLifecycleMixin._save_device_id
)
CryptoStorePersistMixin._clear_olm_data = (
    CryptoStorePersistLifecycleMixin._clear_olm_data
)
CryptoStorePersistMixin.device_id_changed = CryptoStorePersistLifecycleMixin.__dict__[
    "device_id_changed"
]
CryptoStorePersistMixin._load_all = CryptoStorePersistLoadingMixin._load_all


__all__ = [
    "Any",
    "CryptoStorePersistCompatibilityMixin",
    "CryptoStorePersistLifecycleMixin",
    "CryptoStorePersistLoadingMixin",
    "CryptoStorePersistMixin",
    "CryptoStorePersistQueueMixin",
    "CryptoStorePersistRecordsMixin",
    "Future",
    "Path",
    "copy",
    "logger",
    "wait",
]

"""Composable CryptoStore account, session, metadata, and device accessors."""

import copy
import time
from typing import Any

from .account import CryptoStoreAccountSessionsMixin
from .devices import CryptoStoreDeviceSessionsMixin
from .inbound import (
    _MAX_REPLAY_INDEXES_PER_SESSION,
    CryptoStoreMegolmInboundSessionsMixin,
)
from .olm import CryptoStoreOlmSessionsMixin
from .outbound import CryptoStoreMegolmOutboundSessionsMixin


class CryptoStoreSessionsMixin(
    CryptoStoreAccountSessionsMixin,
    CryptoStoreOlmSessionsMixin,
    CryptoStoreMegolmInboundSessionsMixin,
    CryptoStoreMegolmOutboundSessionsMixin,
    CryptoStoreDeviceSessionsMixin,
):
    """Session access split by account, Olm, Megolm, and device domains."""

    pass


# Preserve direct method attributes exposed by the former mixin.
CryptoStoreSessionsMixin.get_account_pickle = (
    CryptoStoreAccountSessionsMixin.get_account_pickle
)
CryptoStoreSessionsMixin.save_account_pickle = (
    CryptoStoreAccountSessionsMixin.save_account_pickle
)
CryptoStoreSessionsMixin.clear_account_pickle = (
    CryptoStoreAccountSessionsMixin.clear_account_pickle
)
CryptoStoreSessionsMixin.get_olm_sessions = CryptoStoreOlmSessionsMixin.get_olm_sessions
CryptoStoreSessionsMixin.add_olm_session = CryptoStoreOlmSessionsMixin.add_olm_session
CryptoStoreSessionsMixin.update_olm_session = (
    CryptoStoreOlmSessionsMixin.update_olm_session
)
CryptoStoreSessionsMixin.replace_olm_sessions = (
    CryptoStoreOlmSessionsMixin.replace_olm_sessions
)
CryptoStoreSessionsMixin.clear_olm_sessions = (
    CryptoStoreOlmSessionsMixin.clear_olm_sessions
)
CryptoStoreSessionsMixin.get_megolm_inbound = (
    CryptoStoreMegolmInboundSessionsMixin.get_megolm_inbound
)
CryptoStoreSessionsMixin.get_megolm_inbound_ids = (
    CryptoStoreMegolmInboundSessionsMixin.get_megolm_inbound_ids
)
CryptoStoreSessionsMixin.save_megolm_inbound = (
    CryptoStoreMegolmInboundSessionsMixin.save_megolm_inbound
)
CryptoStoreSessionsMixin.save_megolm_inbound_metadata = (
    CryptoStoreMegolmInboundSessionsMixin.save_megolm_inbound_metadata
)
CryptoStoreSessionsMixin.get_megolm_inbound_metadata = (
    CryptoStoreMegolmInboundSessionsMixin.get_megolm_inbound_metadata
)
CryptoStoreSessionsMixin.bind_megolm_inbound_sender_user = (
    CryptoStoreMegolmInboundSessionsMixin.bind_megolm_inbound_sender_user
)
CryptoStoreSessionsMixin.check_and_record_megolm_message_index = (
    CryptoStoreMegolmInboundSessionsMixin.check_and_record_megolm_message_index
)
CryptoStoreSessionsMixin.has_megolm_inbound = (
    CryptoStoreMegolmInboundSessionsMixin.has_megolm_inbound
)
CryptoStoreSessionsMixin.get_megolm_inbound_count = (
    CryptoStoreMegolmInboundSessionsMixin.get_megolm_inbound_count
)
CryptoStoreSessionsMixin.get_megolm_outbound = (
    CryptoStoreMegolmOutboundSessionsMixin.get_megolm_outbound
)
CryptoStoreSessionsMixin.save_megolm_outbound = (
    CryptoStoreMegolmOutboundSessionsMixin.save_megolm_outbound
)
CryptoStoreSessionsMixin.save_megolm_outbound_metadata = (
    CryptoStoreMegolmOutboundSessionsMixin.save_megolm_outbound_metadata
)
CryptoStoreSessionsMixin.get_megolm_outbound_metadata = (
    CryptoStoreMegolmOutboundSessionsMixin.get_megolm_outbound_metadata
)
CryptoStoreSessionsMixin.record_megolm_outbound_message = (
    CryptoStoreMegolmOutboundSessionsMixin.record_megolm_outbound_message
)
CryptoStoreSessionsMixin.delete_megolm_outbound = (
    CryptoStoreMegolmOutboundSessionsMixin.delete_megolm_outbound
)
CryptoStoreSessionsMixin.get_megolm_outbound_rooms = (
    CryptoStoreMegolmOutboundSessionsMixin.get_megolm_outbound_rooms
)
CryptoStoreSessionsMixin.get_device_keys = (
    CryptoStoreDeviceSessionsMixin.get_device_keys
)
CryptoStoreSessionsMixin.save_device_keys = (
    CryptoStoreDeviceSessionsMixin.save_device_keys
)
CryptoStoreSessionsMixin.replace_user_device_keys = (
    CryptoStoreDeviceSessionsMixin.replace_user_device_keys
)
CryptoStoreSessionsMixin.delete_user_device_keys = (
    CryptoStoreDeviceSessionsMixin.delete_user_device_keys
)
CryptoStoreSessionsMixin.get_all_device_keys = (
    CryptoStoreDeviceSessionsMixin.get_all_device_keys
)


__all__ = [
    "Any",
    "CryptoStoreAccountSessionsMixin",
    "CryptoStoreDeviceSessionsMixin",
    "CryptoStoreMegolmInboundSessionsMixin",
    "CryptoStoreMegolmOutboundSessionsMixin",
    "CryptoStoreOlmSessionsMixin",
    "CryptoStoreSessionsMixin",
    "_MAX_REPLAY_INDEXES_PER_SESSION",
    "copy",
    "time",
]

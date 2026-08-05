"""Record keys and persistence constants for the crypto store."""


class CryptoStoreCoreConstantsMixin:
    """Shared record keys and persistence tuning constants."""

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


__all__ = ["CryptoStoreCoreConstantsMixin"]

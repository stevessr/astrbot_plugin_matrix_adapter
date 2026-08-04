"""Megolm inbound-session storage, metadata, and replay protection."""

from .core import CryptoStoreMegolmInboundSessionsCoreMixin
from .metadata import CryptoStoreMegolmInboundSessionsMetadataMixin
from .replay import (
    _MAX_REPLAY_INDEXES_PER_SESSION,
    CryptoStoreMegolmInboundSessionsReplayMixin,
)


class CryptoStoreMegolmInboundSessionsMixin(
    CryptoStoreMegolmInboundSessionsCoreMixin,
    CryptoStoreMegolmInboundSessionsMetadataMixin,
    CryptoStoreMegolmInboundSessionsReplayMixin,
):
    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    CryptoStoreMegolmInboundSessionsCoreMixin,
    CryptoStoreMegolmInboundSessionsMetadataMixin,
    CryptoStoreMegolmInboundSessionsReplayMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(CryptoStoreMegolmInboundSessionsMixin, _name, _method)

__all__ = [
    "_MAX_REPLAY_INDEXES_PER_SESSION",
    "CryptoStoreMegolmInboundSessionsMixin",
]

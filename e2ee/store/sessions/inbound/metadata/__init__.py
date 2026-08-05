"""Megolm inbound-session provenance and metadata storage."""

from .normalize import CryptoStoreMegolmInboundMetadataNormalizeMixin
from .query import CryptoStoreMegolmInboundMetadataQueryMixin
from .save import CryptoStoreMegolmInboundMetadataSaveMixin


class CryptoStoreMegolmInboundSessionsMetadataMixin(
    CryptoStoreMegolmInboundMetadataSaveMixin,
    CryptoStoreMegolmInboundMetadataQueryMixin,
    CryptoStoreMegolmInboundMetadataNormalizeMixin,
):
    """Megolm inbound-session provenance and metadata storage."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    CryptoStoreMegolmInboundMetadataSaveMixin,
    CryptoStoreMegolmInboundMetadataQueryMixin,
    CryptoStoreMegolmInboundMetadataNormalizeMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(
                CryptoStoreMegolmInboundSessionsMetadataMixin,
                _method_name,
                _method,
            )


__all__ = ["CryptoStoreMegolmInboundSessionsMetadataMixin"]

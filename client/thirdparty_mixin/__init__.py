"""Composable Matrix third-party protocol lookup operations."""

from typing import Any  # noqa: F401

from ..path_utils import quote_path_segment  # noqa: F401
from .lookups import ThirdPartyLookupMixin
from .protocols import ThirdPartyProtocolMixin


class ThirdPartyMixin(
    ThirdPartyProtocolMixin,
    ThirdPartyLookupMixin,
):
    """Third-party protocol lookup methods for Matrix client."""

    pass


# Preserve direct method attributes exposed by the former mixin.
ThirdPartyMixin.get_thirdparty_protocols = ThirdPartyProtocolMixin.__dict__[
    "get_thirdparty_protocols"
]
ThirdPartyMixin.get_thirdparty_protocol = ThirdPartyLookupMixin.__dict__[
    "get_thirdparty_protocol"
]
ThirdPartyMixin.get_thirdparty_location = ThirdPartyLookupMixin.__dict__[
    "get_thirdparty_location"
]
ThirdPartyMixin.get_thirdparty_user = ThirdPartyLookupMixin.__dict__[
    "get_thirdparty_user"
]


__all__ = ["Any", "ThirdPartyMixin", "quote_path_segment"]

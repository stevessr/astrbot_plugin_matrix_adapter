from .inbound import (
    OlmMachineMegolmInboundMixin,
    _convert_session_key_v2_to_v1,
)
from .outbound import OlmMachineMegolmOutboundMixin


class OlmMachineMegolmMixin(
    OlmMachineMegolmInboundMixin,
    OlmMachineMegolmOutboundMixin,
):
    """Combined mixin."""

    pass

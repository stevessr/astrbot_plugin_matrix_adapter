from .inbound import OlmMachineMegolmInboundMixin
from .outbound import OlmMachineMegolmOutboundMixin


class OlmMachineMegolmMixin(
    OlmMachineMegolmInboundMixin,
    OlmMachineMegolmOutboundMixin,
):
    """Combined mixin."""

    pass

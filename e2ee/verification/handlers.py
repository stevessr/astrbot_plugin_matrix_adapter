from .flow_key import SASVerificationFlowKeyMixin
from .flow_start import SASVerificationFlowStartMixin


class SASVerificationFlowHandlersMixin(
    SASVerificationFlowStartMixin, SASVerificationFlowKeyMixin
):
    """Combined verification flow handlers mixin"""

    pass

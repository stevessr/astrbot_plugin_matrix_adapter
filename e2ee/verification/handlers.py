from ..verification_flow_key import SASVerificationFlowKeyMixin
from ..verification_flow_start import SASVerificationFlowStartMixin


class SASVerificationFlowHandlersMixin(SASVerificationFlowStartMixin, SASVerificationFlowKeyMixin):
    """Combined verification flow handlers mixin"""
    pass

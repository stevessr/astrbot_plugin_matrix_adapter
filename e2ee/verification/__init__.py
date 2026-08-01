from .handlers import SASVerificationFlowHandlersMixin
from .utils import SASVerificationFlowUtilsMixin


class SASVerificationFlowMixin(
    SASVerificationFlowHandlersMixin,
    SASVerificationFlowUtilsMixin,
):
    """Combined mixin."""

    pass



__all__ = ["SASVerification", "SASVerificationFlowMixin"]


def __getattr__(name: str):
    if name == "SASVerification":
        from .sas import SASVerification

        return SASVerification
    raise AttributeError(name)

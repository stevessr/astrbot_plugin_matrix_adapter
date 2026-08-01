"""E2EE requests sub-package."""

from .recover import E2EEManagerRequestsRecoverMixin
from .respond import E2EEManagerRequestsRespondMixin


class E2EEManagerRequestsMixin(
    E2EEManagerRequestsRecoverMixin,
    E2EEManagerRequestsRespondMixin,
):
    """Handles room-key requests, Olm recovery, and m.no_olm."""

    pass

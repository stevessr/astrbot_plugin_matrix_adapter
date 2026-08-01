from .encrypt import E2EEManagerSessionEncryptMixin
from .share import E2EEManagerSessionShareMixin


class E2EEManagerSessionsMixin(
    E2EEManagerSessionShareMixin,
    E2EEManagerSessionEncryptMixin,
):
    """Combined mixin."""

    pass

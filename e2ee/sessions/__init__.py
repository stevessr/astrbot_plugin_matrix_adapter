from .share import E2EEManagerSessionShareMixin
from .encrypt import E2EEManagerSessionEncryptMixin


class E2EEManagerSessionsMixin(
    E2EEManagerSessionShareMixin,
    E2EEManagerSessionEncryptMixin,
):
    """Combined mixin."""
    pass

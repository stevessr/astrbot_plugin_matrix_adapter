from .events import E2EEManagerDecryptEventsMixin
from .validate import E2EEManagerDecryptValidateMixin


class E2EEManagerDecryptMixin(
    E2EEManagerDecryptEventsMixin,
    E2EEManagerDecryptValidateMixin,
):
    """Combined mixin."""
    pass

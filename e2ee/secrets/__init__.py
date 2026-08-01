from .handlers import E2EEManagerSecretsHandlersMixin
from .crypto import E2EEManagerSecretsCryptoMixin


class E2EEManagerSecretsMixin(
    E2EEManagerSecretsHandlersMixin,
    E2EEManagerSecretsCryptoMixin,
):
    """Combined mixin."""
    pass

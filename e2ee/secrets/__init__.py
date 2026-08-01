from .crypto import E2EEManagerSecretsCryptoMixin
from .handlers import E2EEManagerSecretsHandlersMixin


class E2EEManagerSecretsMixin(
    E2EEManagerSecretsHandlersMixin,
    E2EEManagerSecretsCryptoMixin,
):
    """Combined mixin."""

    pass

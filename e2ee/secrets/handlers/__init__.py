"""Device-to-device secret request and response handlers."""

from .client import E2EEManagerSecretsClientMixin
from .receive import E2EEManagerSecretsReceiveMixin
from .request import E2EEManagerSecretsRequestMixin
from .send import E2EEManagerSecretsSendMixin


class E2EEManagerSecretsHandlersMixin(
    E2EEManagerSecretsRequestMixin,
    E2EEManagerSecretsSendMixin,
    E2EEManagerSecretsReceiveMixin,
    E2EEManagerSecretsClientMixin,
):
    """处理设备间秘密共享请求/响应流程的 Mixin。"""

    pass


# Keep the former monolithic mixin's methods in the combined class namespace.
# Besides preserving introspection compatibility, this makes the package split
# transparent to classes that explicitly inspect ``__dict__``.
for _method_name in (
    "handle_secret_request",
    "_get_secret_for_sharing",
    "_send_secret",
    "handle_secret_send",
    "_process_received_secret",
    "request_secret_from_devices",
):
    setattr(
        E2EEManagerSecretsHandlersMixin,
        _method_name,
        getattr(
            {
                "handle_secret_request": E2EEManagerSecretsRequestMixin,
                "_get_secret_for_sharing": E2EEManagerSecretsRequestMixin,
                "_send_secret": E2EEManagerSecretsSendMixin,
                "handle_secret_send": E2EEManagerSecretsReceiveMixin,
                "_process_received_secret": E2EEManagerSecretsReceiveMixin,
                "request_secret_from_devices": E2EEManagerSecretsClientMixin,
            }[_method_name],
            _method_name,
        ),
    )


__all__ = [
    "E2EEManagerSecretsClientMixin",
    "E2EEManagerSecretsHandlersMixin",
    "E2EEManagerSecretsReceiveMixin",
    "E2EEManagerSecretsRequestMixin",
    "E2EEManagerSecretsSendMixin",
]

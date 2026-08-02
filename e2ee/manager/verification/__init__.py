"""Composable E2EE manager verification helpers."""

from .cross_signing import E2EEManagerVerificationCrossSigningMixin
from .devices import E2EEManagerVerificationDevicesMixin
from .events import E2EEManagerVerificationEventsMixin
from .secrets import E2EEManagerVerificationSecretsMixin


class E2EEManagerVerificationMixin(
    E2EEManagerVerificationCrossSigningMixin,
    E2EEManagerVerificationEventsMixin,
    E2EEManagerVerificationSecretsMixin,
    E2EEManagerVerificationDevicesMixin,
):
    """管理设备验证、cross-signing 信任和验证后秘密恢复。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
E2EEManagerVerificationMixin._extract_cross_signing_key_id = staticmethod(
    E2EEManagerVerificationCrossSigningMixin._extract_cross_signing_key_id
)

for _method_name in (
    "_classify_own_device_cross_signing_state",
    "_format_masked_device_ids",
    "_log_manual_same_user_verification_required",
    "_log_same_user_verification_gap",
    "_maybe_republish_current_device_keys_after_verification",
    "publish_trusted_device",
):
    setattr(
        E2EEManagerVerificationMixin,
        _method_name,
        getattr(E2EEManagerVerificationCrossSigningMixin, _method_name),
    )

for _method_name in (
    "handle_verification_event",
    "handle_in_room_verification_event",
):
    setattr(
        E2EEManagerVerificationMixin,
        _method_name,
        getattr(E2EEManagerVerificationEventsMixin, _method_name),
    )

E2EEManagerVerificationMixin.request_missing_secrets_after_verification = (
    E2EEManagerVerificationSecretsMixin.request_missing_secrets_after_verification
)

for _method_name in (
    "_verify_untrusted_own_devices",
    "_initiate_verification_for_device",
):
    setattr(
        E2EEManagerVerificationMixin,
        _method_name,
        getattr(E2EEManagerVerificationDevicesMixin, _method_name),
    )

__all__ = [
    "E2EEManagerVerificationCrossSigningMixin",
    "E2EEManagerVerificationDevicesMixin",
    "E2EEManagerVerificationEventsMixin",
    "E2EEManagerVerificationMixin",
    "E2EEManagerVerificationSecretsMixin",
]

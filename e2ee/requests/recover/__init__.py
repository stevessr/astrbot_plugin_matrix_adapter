"""Composable E2EE request recovery mixins."""

from .room_key import E2EEManagerRequestsRoomKeyMixin
from .session import E2EEManagerRequestsSessionMixin
from .trust import E2EEManagerRequestsTrustMixin
from .withheld import E2EEManagerRequestsWithheldMixin


class E2EEManagerRequestsRecoverMixin(
    E2EEManagerRequestsSessionMixin,
    E2EEManagerRequestsRoomKeyMixin,
    E2EEManagerRequestsWithheldMixin,
    E2EEManagerRequestsTrustMixin,
):
    """Handles Olm recovery, room-key requests, and withheld events."""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _method_name in (
    "_request_new_session",
    "_mark_olm_send_succeeded",
):
    setattr(
        E2EEManagerRequestsRecoverMixin,
        _method_name,
        getattr(E2EEManagerRequestsSessionMixin, _method_name),
    )

for _method_name in (
    "_request_room_key",
    "_cancel_room_key_request",
):
    setattr(
        E2EEManagerRequestsRecoverMixin,
        _method_name,
        getattr(E2EEManagerRequestsRoomKeyMixin, _method_name),
    )

for _method_name in (
    "_send_room_key_withheld",
    "_send_no_olm_withheld",
    "handle_room_key_withheld",
):
    setattr(
        E2EEManagerRequestsRecoverMixin,
        _method_name,
        getattr(E2EEManagerRequestsWithheldMixin, _method_name),
    )

E2EEManagerRequestsRecoverMixin._is_own_device_trusted = (
    E2EEManagerRequestsTrustMixin._is_own_device_trusted
)

__all__ = [
    "E2EEManagerRequestsRecoverMixin",
    "E2EEManagerRequestsRoomKeyMixin",
    "E2EEManagerRequestsSessionMixin",
    "E2EEManagerRequestsTrustMixin",
    "E2EEManagerRequestsWithheldMixin",
]

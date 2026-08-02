"""Layered extended profile and selective presence mixins."""

from astrbot.api import logger  # noqa: F401

from .basic import ProfileBasicMixin
from .capability import PresenceCapabilityMixin
from .prompted import PresencePromptedMixin
from .sharing import PresenceSharingMixin


class ProfileExtendedMixin(
    ProfileBasicMixin,
    PresenceSharingMixin,
    PresencePromptedMixin,
    PresenceCapabilityMixin,
):
    """Extended profile and presence methods for Matrix client."""

    pass


# Preserve the historical direct method surface for introspection and callers
# that use ProfileExtendedMixin as a standalone mixin.
ProfileExtendedMixin.set_presence = ProfileBasicMixin.set_presence
ProfileExtendedMixin.get_presence = ProfileBasicMixin.get_presence
ProfileExtendedMixin.get_extended_profile = ProfileBasicMixin.get_extended_profile
ProfileExtendedMixin.set_extended_profile_field = (
    ProfileBasicMixin.set_extended_profile_field
)
ProfileExtendedMixin.delete_extended_profile_field = (
    ProfileBasicMixin.delete_extended_profile_field
)
ProfileExtendedMixin._validate_presence_sharing_maps = (
    PresenceSharingMixin._validate_presence_sharing_maps
)
ProfileExtendedMixin.get_presence_sharing_prefs = (
    PresenceSharingMixin.get_presence_sharing_prefs
)
ProfileExtendedMixin.set_presence_sharing_prefs = (
    PresenceSharingMixin.set_presence_sharing_prefs
)
ProfileExtendedMixin.get_presence_prompted = PresencePromptedMixin.get_presence_prompted
ProfileExtendedMixin.set_presence_prompted = PresencePromptedMixin.set_presence_prompted
ProfileExtendedMixin._modify_presence_prompted = (
    PresencePromptedMixin._modify_presence_prompted
)
ProfileExtendedMixin.add_presence_prompted = PresencePromptedMixin.add_presence_prompted
ProfileExtendedMixin.remove_presence_prompted = (
    PresencePromptedMixin.remove_presence_prompted
)
ProfileExtendedMixin.get_selective_presence_capability = (
    PresenceCapabilityMixin.get_selective_presence_capability
)
ProfileExtendedMixin.set_room_presence_sharing = (
    PresenceCapabilityMixin.set_room_presence_sharing
)
ProfileExtendedMixin.get_room_presence_sharing = (
    PresenceCapabilityMixin.get_room_presence_sharing
)

__all__ = [
    "ProfileExtendedMixin",
    "ProfileBasicMixin",
    "PresenceSharingMixin",
    "PresencePromptedMixin",
    "PresenceCapabilityMixin",
]

from .share_events import E2EEManagerSessionShareEventsMixin
from .share_keys import E2EEManagerSessionShareKeysMixin


class E2EEManagerSessionShareMixin(
    E2EEManagerSessionShareEventsMixin, E2EEManagerSessionShareKeysMixin
):
    """Combined room-key share mixin"""

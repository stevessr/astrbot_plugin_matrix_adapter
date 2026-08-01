from .media import SenderMediaMixin
from .room import SenderRoomMixin


class SenderMixin(SenderMediaMixin, SenderRoomMixin):
    """Combined sender mixin."""

    pass


__all__ = ["SenderMediaMixin", "SenderRoomMixin", "SenderMixin"]

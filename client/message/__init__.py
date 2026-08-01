from .receipts import MessageReceiptsMixin
from .send import MessageSendMixin

__all__ = ["MessageSendMixin", "MessageReceiptsMixin"]


class MessageMixin(
    MessageSendMixin,
    MessageReceiptsMixin,
):
    """Combined mixin."""

    pass

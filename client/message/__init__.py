from .receipts import MessageReceiptsMixin
from .send import MessageSendMixin

__all__ = ["MessageSendMixin", "MessageReceiptsMixin"]


class MessageMixin(
    MessageSendMixin,
    MessageReceiptsMixin,
):
    """Combined mixin."""

    pass

    # Keep the primary send method visible on the historical combined class
    # for callers that inspect the class dictionary.
    send_message = MessageSendMixin.send_message

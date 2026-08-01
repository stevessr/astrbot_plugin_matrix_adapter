from .send import MessageSendMixin
from .receipts import MessageReceiptsMixin


__all__ = ['MessageSendMixin', 'MessageReceiptsMixin']

class MessageMixin(
    MessageSendMixin,
    MessageReceiptsMixin,
):
    """Combined mixin."""
    pass

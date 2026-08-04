"""FC-boundary reply injection for tool-call message chains."""

from astrbot.api import logger
from astrbot.api.message_components import Reply as _Reply


class MatrixPlatformEventSendFcMixin:
    """Inject a reply segment at function-call boundaries."""

    def _prepare_fc_boundary(self, message_chain) -> bool:
        """Inject a Reply for tool-call boundaries; return is_fc_boundary."""
        is_fc_boundary = message_chain.type in {"tool_call", "tool_direct_result"}
        if is_fc_boundary:
            try:
                has_reply = any(
                    isinstance(seg, _Reply) for seg in message_chain.chain or []
                )
                reply_id = getattr(self.message_obj, "message_id", None)
                sender_id = getattr(
                    getattr(self.message_obj, "sender", None),
                    "user_id",
                    None,
                )
                if not has_reply and reply_id:
                    message_chain.chain.insert(
                        0,
                        _Reply(id=reply_id, sender_id=sender_id),
                    )
            except Exception:
                logger.debug("FC 边界 Reply 处理失败")
        return is_fc_boundary

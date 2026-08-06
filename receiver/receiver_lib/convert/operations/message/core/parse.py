"""Reply-relation parsing for message conversion."""

from .......constants import REL_TYPE_THREAD


class MatrixReceiverMessageConvertParseMixin:
    """Parse reply and thread relations from event content."""

    def _parse_reply_event_id(self, event_content: dict) -> str | None:
        """Extract the reply target event id from m.relates_to."""
        relates_to = event_content.get("m.relates_to", {})
        reply_event_id = None
        if isinstance(relates_to, dict):
            in_reply_to = relates_to.get("m.in_reply_to")
            if isinstance(in_reply_to, dict):
                reply_event_id = in_reply_to.get("event_id")
            if not reply_event_id and relates_to.get("rel_type") == REL_TYPE_THREAD:
                reply_event_id = relates_to.get("event_id")
        return reply_event_id


__all__ = ["MatrixReceiverMessageConvertParseMixin"]
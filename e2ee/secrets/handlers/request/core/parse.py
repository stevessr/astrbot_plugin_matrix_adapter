"""Incoming secret request parsing."""


class E2EEManagerSecretsRequestParseMixin:
    """Extract fields from an incoming m.secret.request event."""

    def _parse_secret_request(
        self,
        content: dict,
        sender_device: str,
    ) -> tuple | None:
        """Return ``(action, requesting_device_id, request_id, name)``."""
        if not isinstance(content, dict):
            return None
        action = content.get("action")
        # Prefer the authenticated sender_device from to-device metadata over
        # the unauthenticated requesting_device_id inside the event content
        # (defense-in-depth; the device is still verified later).
        requesting_device_id = sender_device or content.get(
            "requesting_device_id", sender_device
        )
        request_id = content.get("request_id", "")
        name = content.get("name", "")
        return action, requesting_device_id, request_id, name


__all__ = ["E2EEManagerSecretsRequestParseMixin"]

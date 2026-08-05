"""Matrix Olm envelope construction."""


class OlmMachineMessageEnvelopeMixin:
    """Build the Matrix protocol wrapper for Olm payloads."""

    def _build_olm_envelope(
        self,
        content: dict,
        recipient_user_id: str,
        recipient_ed25519_key: str,
        event_type: str,
    ) -> dict:
        # 构造 Matrix 协议外壳
        wrapper = {
            "sender": self.user_id,
            "sender_device": self.device_id,
            "keys": {"ed25519": self.ed25519_key},
            # Matrix v1.15+ (MSC4147): carrying the signed device object lets
            # the receiver validate the sender without a racy /keys/query.
            "sender_device_keys": self.get_device_keys(),
            "recipient": recipient_user_id,
            "recipient_keys": {"ed25519": recipient_ed25519_key},
            "type": event_type,
            "content": content,
        }
        return wrapper


__all__ = ["OlmMachineMessageEnvelopeMixin"]

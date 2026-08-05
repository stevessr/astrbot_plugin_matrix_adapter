"""Inbound MAC recording."""


class SASVerificationFlowMACRecordMixin:
    """Persist the received MAC into the verification session."""

    def _record_mac_received(self, session, their_mac):
        session["their_mac"] = their_mac
        session["state"] = "mac_received"


__all__ = ["SASVerificationFlowMACRecordMixin"]

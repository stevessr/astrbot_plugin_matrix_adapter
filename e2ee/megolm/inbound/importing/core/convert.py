"""Megolm session key conversion and import."""

from astrbot.api import logger

from .....olm.types import ExportedSessionKey, InboundGroupSession
from ...conversion import _convert_session_key_v2_to_v1


class OlmMachineMegolmInboundImportConvertMixin:
    """Import a Megolm session key payload into an inbound session."""

    def _import_megolm_session(self, session_key, session_id):
        if isinstance(session_key, str):
            # Both full SessionKey (v2) and exported/ratcheted key (v1)
            # payloads are normalized to the import format.
            converted_key = _convert_session_key_v2_to_v1(session_key)
            session = InboundGroupSession.import_session(
                ExportedSessionKey(converted_key)
            )
        else:
            session = InboundGroupSession(session_key)

        if session.session_id != session_id:
            logger.warning("Rejected Megolm key whose derived session ID mismatches")
            return None
        return session

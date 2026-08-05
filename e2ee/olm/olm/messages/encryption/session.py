"""Olm encryption session resolution."""

from astrbot.api import logger


class OlmMachineMessageEncryptSessionMixin:
    """Resolve the Olm session used for encryption."""

    def _resolve_olm_encrypt_session(
        self,
        their_identity_key: str,
        session,
    ):
        """Return ``(session, session_index)``, raising when unavailable."""
        masked_identity_key = (their_identity_key or "")[:8]
        session_index: int | None = None
        if not session:
            # 尝试使用现有会话
            sessions = self._olm_sessions.get(their_identity_key, [])
            if sessions:
                session_index = len(sessions) - 1
                session = sessions[session_index]
                logger.debug(f"使用现有 Olm 会话对 {masked_identity_key}... 加密")
            else:
                logger.warning(f"没有可用于 {masked_identity_key}... 的 Olm 会话")
                raise RuntimeError(f"没有可用于 {their_identity_key} 的 Olm 会话")
        else:
            sessions = self._olm_sessions.get(their_identity_key, [])
            if sessions:
                for idx, existing in enumerate(sessions):
                    if existing is session:
                        session_index = idx
                        break
                if session_index is None:
                    session_index = len(sessions) - 1
        return session, session_index


__all__ = ["OlmMachineMessageEncryptSessionMixin"]

"""UIA authentication helpers for cross-signing uploads."""

from ....client.http_client import MatrixAPIError
from ....constants import LOGIN_TYPE_PASSWORD


class CrossSigningCryptoAuthMixin:
    """构造密码认证并提取 UIA session。"""

    def _build_password_auth(self, session_id: str) -> dict:
        return {
            "type": LOGIN_TYPE_PASSWORD,
            "identifier": {"type": "m.id.user", "user": self.user_id},
            "password": self.password,
            "session": session_id,
        }

    @staticmethod
    def _extract_uia_session(error: MatrixAPIError) -> str | None:
        data = getattr(error, "data", None)
        if isinstance(data, dict):
            session = data.get("session")
            return session if isinstance(session, str) and session else None
        return None

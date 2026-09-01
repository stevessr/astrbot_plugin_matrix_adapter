"""UIA authentication helpers for cross-signing uploads."""

from urllib.parse import urlsplit

from ....client.http_client import MatrixAPIError
from ....constants import LOGIN_TYPE_OAUTH, LOGIN_TYPE_PASSWORD


class CrossSigningCryptoAuthMixin:
    """Build and inspect UIA authentication for cross-signing uploads."""

    def _build_password_auth(self, session_id: str) -> dict:
        return {
            "type": LOGIN_TYPE_PASSWORD,
            "identifier": {"type": "m.id.user", "user": self.user_id},
            "password": self.password,
            "session": session_id,
        }

    @staticmethod
    def _extract_uia_data(error: MatrixAPIError) -> dict:
        data = getattr(error, "data", None)
        return data if isinstance(data, dict) else {}

    @classmethod
    def _extract_uia_session(cls, error: MatrixAPIError) -> str | None:
        session = cls._extract_uia_data(error).get("session")
        return session if isinstance(session, str) and session else None

    @classmethod
    def _uia_supports_stage(cls, error: MatrixAPIError, stage: str) -> bool:
        flows = cls._extract_uia_data(error).get("flows")
        if not isinstance(flows, list):
            return False
        for flow in flows:
            if not isinstance(flow, dict):
                continue
            stages = flow.get("stages")
            if isinstance(stages, list) and stage in stages:
                return True
        return False

    @classmethod
    def _extract_oauth_uia_approval(cls, error: MatrixAPIError) -> dict | None:
        """Return the stable Matrix v1.17 ``m.oauth`` approval challenge.

        A valid challenge requires both the UIA session and the HTTP(S) account
        management URL from ``params.m.oauth.url``. Callers deliberately treat a
        malformed advertised ``m.oauth`` stage as fatal instead of weakening the
        flow to password UIA.
        """
        if not cls._uia_supports_stage(error, LOGIN_TYPE_OAUTH):
            return None

        data = cls._extract_uia_data(error)
        session_id = cls._extract_uia_session(error)
        params = data.get("params")
        oauth_params = params.get(LOGIN_TYPE_OAUTH) if isinstance(params, dict) else None
        url = oauth_params.get("url") if isinstance(oauth_params, dict) else None
        if not session_id or not isinstance(url, str) or not url:
            raise RuntimeError("Malformed m.oauth UIA challenge: missing session or URL")

        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise RuntimeError("Malformed m.oauth UIA challenge: invalid approval URL")
        return {"session": session_id, "url": url}

    @staticmethod
    def _build_oauth_uia_completion(session_id: str) -> dict:
        """Complete MSC4312 after the user approved the action out-of-band.

        The stable flow intentionally sends only the UIA session: the approval
        happened in the OAuth account-management UI and there is no OAuth token
        or ``type`` field to submit in the UIA payload.
        """
        return {"session": session_id}

"""Token login payload construction."""

from .....constants import LOGIN_TYPE_TOKEN


class AuthLoginCredentialsTokenMixin:
    """Build token login payloads."""

    def _build_token_login_data(
        self,
        token: str,
        device_name: str,
        device_id: str | None,
    ) -> dict:
        data = {
            "type": LOGIN_TYPE_TOKEN,
            "token": token,
            "initial_device_display_name": device_name,
        }
        if device_id:
            data["device_id"] = device_id
        return data


__all__ = ["AuthLoginCredentialsTokenMixin"]

"""Token login payload construction."""

from .....constants import LOGIN_TYPE_TOKEN


class AuthLoginCredentialsTokenMixin:
    """Build token login payloads."""

    def _build_token_login_data(
        self,
        token: str,
        device_name: str,
        device_id: str | None,
        request_refresh_token: bool = True,
    ) -> dict:
        data = {
            "type": LOGIN_TYPE_TOKEN,
            "token": token,
            "initial_device_display_name": device_name,
            # Matrix v1.3 / MSC2918: request a refresh token explicitly.
            "refresh_token": bool(request_refresh_token),
        }
        if device_id:
            data["device_id"] = device_id
        return data


__all__ = ["AuthLoginCredentialsTokenMixin"]

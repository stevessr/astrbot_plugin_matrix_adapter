"""Validation rules for Matrix configuration."""


class MatrixConfigValidationMixin:
    """Validate required authentication and server settings."""

    def _validate(self):
        if not self.user_id and self.auth_method != "oauth2":
            raise ValueError(
                "matrix_user_id is required in configuration. Format: @username:homeserver.com"
            )
        if not self.homeserver:
            raise ValueError(
                "matrix_homeserver is required in configuration. Example: https://matrix.org"
            )

        valid_auth_methods = ["password", "token", "oauth2", "qr"]
        if self.auth_method not in valid_auth_methods:
            raise ValueError(
                f"Invalid matrix_auth_method: {self.auth_method}. Must be one of: {', '.join(valid_auth_methods)}"
            )

        if self.auth_method == "password" and not self.password:
            raise ValueError(
                "matrix_password is required when matrix_auth_method='password'"
            )

        if self.auth_method == "token" and not self.access_token:
            raise ValueError(
                "matrix_access_token is required when matrix_auth_method='token'"
            )

        # OAuth2: client_id is now optional (can be auto-registered if server supports it)
        # No strict validation needed for OAuth2 mode

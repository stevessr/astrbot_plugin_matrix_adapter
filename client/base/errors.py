"""Errors raised by the Matrix HTTP client."""

M_RESOURCE_LIMIT_EXCEEDED = "M_RESOURCE_LIMIT_EXCEEDED"
M_USER_LIMIT_EXCEEDED = "M_USER_LIMIT_EXCEEDED"


class MatrixAPIError(Exception):
    """Matrix API Error with stable errcode helpers."""

    def __init__(self, status: int, data: dict | str, message: str):
        self.status = status
        self.data = data
        self.message = message
        super().__init__(message)

    @property
    def errcode(self) -> str | None:
        """Return the Matrix ``errcode`` when the response is JSON."""
        if isinstance(self.data, dict):
            value = self.data.get("errcode")
            return str(value) if value is not None else None
        return None

    @property
    def is_resource_limit_exceeded(self) -> bool:
        """Whether this is stable ``M_RESOURCE_LIMIT_EXCEEDED``."""
        return self.errcode == M_RESOURCE_LIMIT_EXCEEDED

    @property
    def is_user_limit_exceeded(self) -> bool:
        """Whether this is Matrix v1.18 / MSC4335 ``M_USER_LIMIT_EXCEEDED``."""
        return self.errcode == M_USER_LIMIT_EXCEEDED

    @property
    def admin_contact(self) -> str | None:
        """Return the required admin contact for resource/user limit errors."""
        if not isinstance(self.data, dict):
            return None
        value = self.data.get("admin_contact")
        return str(value) if value is not None else None


__all__ = [
    "M_RESOURCE_LIMIT_EXCEEDED",
    "M_USER_LIMIT_EXCEEDED",
    "MatrixAPIError",
]

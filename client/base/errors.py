"""Errors raised by the Matrix HTTP client."""

M_UNRECOGNIZED = "M_UNRECOGNIZED"
M_RESOURCE_LIMIT_EXCEEDED = "M_RESOURCE_LIMIT_EXCEEDED"
M_USER_LIMIT_EXCEEDED = "M_USER_LIMIT_EXCEEDED"
M_USER_LOCKED = "M_USER_LOCKED"
M_USER_SUSPENDED = "M_USER_SUSPENDED"


class MatrixAPIError(Exception):
    """Matrix API Error with stable errcode helpers."""

    def __init__(self, status: int, data: dict | str, message: str):
        self.status = status
        self.data = data
        self.message = message
        super().__init__(message)

    @property
    def errcode(self) -> str | None:
        if isinstance(self.data, dict):
            value = self.data.get("errcode")
            return str(value) if value is not None else None
        return None

    @property
    def soft_logout(self) -> bool:
        return isinstance(self.data, dict) and self.data.get("soft_logout") is True

    @property
    def is_unrecognized(self) -> bool:
        """Whether the server returned stable ``M_UNRECOGNIZED``."""
        return self.errcode == M_UNRECOGNIZED

    @property
    def is_endpoint_unsupported(self) -> bool:
        """Whether routing failed under MSC3743 semantics.

        Stable Matrix v1.6 uses 404/M_UNRECOGNIZED for an unknown path and
        405/M_UNRECOGNIZED for an unsupported method on a known path.  A plain
        404 such as M_NOT_FOUND is deliberately *not* treated as feature
        absence because it may mean the requested Matrix object does not exist.
        """
        return self.status in {404, 405} and self.errcode == M_UNRECOGNIZED

    @property
    def is_resource_limit_exceeded(self) -> bool:
        return self.errcode == M_RESOURCE_LIMIT_EXCEEDED

    @property
    def is_user_limit_exceeded(self) -> bool:
        return self.errcode == M_USER_LIMIT_EXCEEDED

    @property
    def is_user_locked(self) -> bool:
        return self.errcode == M_USER_LOCKED

    @property
    def is_user_suspended(self) -> bool:
        return self.errcode == M_USER_SUSPENDED

    @property
    def admin_contact(self) -> str | None:
        if not isinstance(self.data, dict):
            return None
        value = self.data.get("admin_contact")
        return str(value) if value is not None else None


__all__ = [
    "M_UNRECOGNIZED",
    "M_RESOURCE_LIMIT_EXCEEDED",
    "M_USER_LIMIT_EXCEEDED",
    "M_USER_LOCKED",
    "M_USER_SUSPENDED",
    "MatrixAPIError",
]

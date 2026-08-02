"""Errors raised by the Matrix HTTP client."""


class MatrixAPIError(Exception):
    """Matrix API Error"""

    def __init__(self, status: int, data: dict | str, message: str):
        self.status = status
        self.data = data
        self.message = message
        super().__init__(message)


__all__ = ["MatrixAPIError"]

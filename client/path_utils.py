"""Helpers for Matrix Client-Server API path parameters."""

from urllib.parse import quote


def quote_path_segment(value: object) -> str:
    """Percent-encode one Matrix path segment.

    Matrix room IDs, aliases, event IDs, txn IDs and state keys may contain
    characters such as ``#``, ``$``, ``/`` or ``:``.  They must be encoded as
    individual path segments before concatenating endpoint strings.
    """
    return quote(str(value), safe="")

"""Attach OAuth state to SSO redirect URLs."""

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def _attach_state_param(url: str, state: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["state"] = state
    return urlunparse(parsed._replace(query=urlencode(query)))

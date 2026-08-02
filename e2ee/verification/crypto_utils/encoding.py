import base64


def _encode_unpadded_base64(data: bytes) -> str:
    """Base64 encode without padding."""
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _decode_base64(value: str) -> bytes:
    """Base64 decode with automatic padding."""
    normalized = value.strip()
    padding = "=" * (-len(normalized) % 4)
    return base64.b64decode(normalized + padding)

"""MXC URL parsing and HTTP URL conversion helpers."""

from urllib.parse import quote


class MatrixUtilsMediaUrlMixin:
    """MXC media URL parsing and conversion to HTTP download URLs."""

    @staticmethod
    def _parse_mxc_url(mxc_url: str) -> tuple[str, str] | None:
        normalized = str(mxc_url or "").strip()
        if not normalized.startswith("mxc://"):
            return None
        parts = normalized[6:].split("/", 1)
        if len(parts) != 2:
            return None
        server_name = parts[0].strip()
        media_id = parts[1].split("?", 1)[0].split("#", 1)[0].strip().lstrip("/")
        if not server_name or not media_id:
            return None
        return server_name, media_id

    @staticmethod
    def mxc_to_http(mxc_url: str, homeserver: str) -> str:
        parsed = MatrixUtilsMediaUrlMixin._parse_mxc_url(mxc_url)
        if parsed is None:
            return mxc_url
        base_url = str(homeserver or "").strip().rstrip("/")
        if not base_url:
            return mxc_url
        server_name, media_id = parsed
        return (
            f"{base_url}/_matrix/client/v1/media/download/"
            f"{quote(server_name, safe='')}/{quote(media_id, safe='')}"
        )

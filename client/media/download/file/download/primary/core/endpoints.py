"""Full-size Matrix media download endpoint building."""


class MediaDownloadPrimaryEndpointMixin:
    """Build media download endpoint lists."""

    def _build_download_endpoint_list(
        self,
        server_path: str,
        media_path: str,
    ) -> list:
        """Build the ordered list of download endpoints to attempt."""
        proxy_endpoints = [
            f"/_matrix/client/v1/media/download/{server_path}/{media_path}",
        ]
        direct_endpoints: list[str] = []
        public_endpoints: list[str] = []

        all_endpoints = (
            [(url, True, "proxy") for url in proxy_endpoints]
            + [(url, False, "direct") for url in direct_endpoints]
            + [(url, False, "public") for url in public_endpoints]
        )
        return all_endpoints


__all__ = ["MediaDownloadPrimaryEndpointMixin"]

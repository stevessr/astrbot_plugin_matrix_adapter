"""OAuth2 HTTP timeout resolution."""


class MatrixOAuth2DiscoveryTimeoutMixin:
    def _get_oauth_http_timeout_seconds(self) -> float:
        resolver = getattr(self, "_resolve_oauth_http_timeout_seconds", None)
        if callable(resolver):
            try:
                return float(resolver(cap_seconds=120))
            except Exception:
                pass
        return 30.0

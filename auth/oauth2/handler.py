"""Matrix OAuth2 authentication handler composition."""

from .config import MatrixOAuth2ConfigMixin
from .discovery import MatrixOAuth2Discovery
from .flow import MatrixOAuth2FlowMixin
from .pkce import MatrixOAuth2PKCE


class MatrixOAuth2(
    MatrixOAuth2ConfigMixin,
    MatrixOAuth2Discovery,
    MatrixOAuth2PKCE,
    MatrixOAuth2FlowMixin,
):
    """Matrix OAuth2 authorization-code handler."""

    pass

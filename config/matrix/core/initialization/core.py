"""Matrix configuration initialization orchestration."""

from .....utils import parse_bool


class MatrixConfigCoreInitializationMixin:
    """Initialize the main Matrix configuration state."""

    _parse_bool = staticmethod(parse_bool)

    @staticmethod
    def _parse_int(
        value: object,
        default: int,
        *,
        minimum: int | None = None,
        maximum: int | None = None,
    ) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = default
        if minimum is not None:
            parsed = max(minimum, parsed)
        if maximum is not None:
            parsed = min(maximum, parsed)
        return parsed

    def __init__(self, config: dict):
        """Initialize Matrix configuration.

        Supported authentication methods: 'password', 'token', 'oauth2', and 'qr'.
        """
        # 创建配置副本以避免修改原始配置对象
        self.config = (config or {}).copy()
        self._initialize_identity_state()
        self._initialize_feature_state()
        self._initialize_e2ee_state()
        self._validate()

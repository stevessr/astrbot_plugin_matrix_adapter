"""Verification algorithm normalization and intersection picking."""


class SASVerificationSendDeviceNegotiationAlgorithmsMixin:
    """协商验证算法并选择需要加入 MAC 的本地身份密钥。"""

    @staticmethod
    def _normalize_algorithm_values(value: object) -> list[str]:
        if isinstance(value, str):
            normalized = value.strip()
            return [normalized] if normalized else []
        if isinstance(value, (list, tuple, set)):
            values: list[str] = []
            for item in value:
                if not isinstance(item, str):
                    continue
                normalized = item.strip()
                if normalized:
                    values.append(normalized)
            return values
        return []

    @staticmethod
    def _pick_algorithm(
        supported: list[str], peer_supported: list[str], fallback: str = ""
    ) -> str:
        for algorithm in supported:
            if algorithm in peer_supported:
                return algorithm
        if supported:
            return supported[0]
        if peer_supported:
            return peer_supported[0]
        return fallback

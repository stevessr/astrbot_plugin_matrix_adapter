"""Core construction for the crypto store."""

from pathlib import Path


class CryptoStoreCoreOrchestratorMixin:
    """E2EE 加密状态存储"""

    def __init__(
        self,
        store_path: str | Path,
        user_id: str,
        device_id: str,
        *,
        namespace_key: str | None = None,
    ):
        """
        初始化加密存储

        Args:
            store_path: 存储目录路径
            user_id: 用户 ID (如 @bot:example.com)
            device_id: 设备 ID
        """
        self.store_path = Path(store_path)
        self.user_id = user_id
        self.device_id = device_id

        self._init_storage_backend(namespace_key)
        self._init_persist_infrastructure()
        self._initializing = True

        self._init_memory_caches()
        self._init_identity_state()
        self._initializing = False


__all__ = ["CryptoStoreCoreOrchestratorMixin"]

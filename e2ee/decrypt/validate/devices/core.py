"""Sender-key resolution orchestration."""


class E2EEManagerDecryptDeviceOrchestratorMixin:
    """Resolve a sender key to a validated user/device pair."""

    async def _find_device_by_sender_key(
        self, sender_key: str, sender_user_id: str | None = None
    ) -> tuple[str, str] | None:
        """
        通过 sender_key 查找对应的用户和设备

        首先检查本地缓存，如果找不到则尝试从服务器查询。

        Args:
            sender_key: 发送者的 curve25519 密钥
            sender_user_id: 可选的发送者用户 ID（如果已知）

        Returns:
            (user_id, device_id) 元组，或 None
        """
        # 1. 首先从本地缓存查找
        cached = self._find_sender_device_in_local_cache(
            sender_key,
            sender_user_id,
        )
        if cached is not None:
            return cached

        # 2. 如果本地没有，且知道发送者用户 ID，则从服务器查询
        if sender_user_id:
            server = await self._find_sender_device_on_server(
                sender_key,
                sender_user_id,
            )
            if server is not None:
                return server

        return None


__all__ = ["E2EEManagerDecryptDeviceOrchestratorMixin"]

"""Identity checks and initial loading for the crypto store."""


class CryptoStoreCoreIdentityMixin:
    """Detect device-id changes and load persisted records."""

    def _init_identity_state(self) -> None:
        # 检查 device_id 是否变化
        self._device_id_changed = self._check_device_id_change()

        # 加载现有数据
        self._load_all()


__all__ = ["CryptoStoreCoreIdentityMixin"]

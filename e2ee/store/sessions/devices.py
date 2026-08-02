class CryptoStoreDeviceSessionsMixin:
    def get_device_keys(
        self, user_id: str, device_id: str | None = None
    ) -> dict[str, dict] | dict[str, str]:
        """获取用户的所有设备密钥"""
        user_keys = self._device_keys.get(user_id, {})
        if device_id is None:
            return user_keys

        raw_device_keys = user_keys.get(device_id, {})
        if not isinstance(raw_device_keys, dict):
            return {}

        keys_obj = raw_device_keys.get("keys", {})
        if not isinstance(keys_obj, dict):
            keys_obj = {}

        curve25519 = keys_obj.get(f"curve25519:{device_id}", "")
        ed25519 = keys_obj.get(f"ed25519:{device_id}", "")
        if not curve25519 and not ed25519:
            return {}

        return {
            "curve25519": curve25519,
            "ed25519": ed25519,
        }

    def save_device_keys(self, user_id: str, device_id: str, keys: dict):
        """保存设备密钥"""
        if user_id not in self._device_keys:
            self._device_keys[user_id] = {}
        self._device_keys[user_id][device_id] = keys
        self._save_record(self._RECORD_DEVICE_KEYS, self._device_keys)

    def replace_user_device_keys(self, user_id: str, devices: dict[str, dict]) -> None:
        """Replace a user's tracked list after a complete /keys/query result."""
        self._device_keys[user_id] = dict(devices)
        self._save_record(self._RECORD_DEVICE_KEYS, self._device_keys)

    def delete_user_device_keys(self, user_id: str) -> None:
        """Forget device keys for a user no longer sharing encrypted rooms."""
        if self._device_keys.pop(user_id, None) is not None:
            self._save_record(self._RECORD_DEVICE_KEYS, self._device_keys)

    def get_all_device_keys(self) -> dict[str, dict]:
        """获取所有已知的设备密钥"""
        return self._device_keys

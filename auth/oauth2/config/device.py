"""OAuth2 device identifier normalization and generation."""

import base64
import secrets


class MatrixOAuth2ConfigDeviceMixin:
    @staticmethod
    def _normalize_device_id(device_id: str | None) -> str | None:
        if not isinstance(device_id, str):
            return None
        normalized = device_id.strip()
        return normalized or None

    def _generate_device_id(self) -> str:
        random_bytes = secrets.token_bytes(9)
        device_id = base64.b64encode(random_bytes).decode("ascii").rstrip("=")
        device_id = device_id.replace("+", "").replace("/", "")

        if len(device_id) < 10:
            device_id += secrets.token_urlsafe(5)[: 15 - len(device_id)]
        elif len(device_id) > 15:
            device_id = device_id[:15]

        return device_id

    def _ensure_device_id(self) -> str:
        if not self.device_id:
            self.device_id = self._generate_device_id()
        return self.device_id

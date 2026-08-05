"""Fetch and validate the target device keys for signing."""

from astrbot.api import logger


class CrossSigningDeviceSignFetchMixin:
    """Fetch the target device keys, repairing the current device when stale."""

    async def _fetch_sign_target_device_keys(self, device_id: str) -> dict | None:
        """Return the target ``device_keys`` dict, or ``None`` when unsigned."""
        repaired_current_device = False
        while True:
            response = await self.client.query_keys({self.user_id: [device_id]})
            device_keys = (
                (response.get("device_keys") or {}).get(self.user_id, {}).get(device_id)
            )
            if not device_keys:
                if (
                    device_id == self.device_id
                    and not repaired_current_device
                    and await self._repair_current_device_keys_once()
                ):
                    repaired_current_device = True
                    continue
                logger.debug("[E2EE-CrossSign] 未找到设备密钥，无法签名")
                return None

            if device_id != self.device_id:
                break

            (
                matches,
                local_ed25519,
                local_curve25519,
                server_ed25519,
                server_curve25519,
            ) = self._current_device_matches_server(device_keys)
            if matches:
                break

            if (
                not repaired_current_device
                and await self._repair_current_device_keys_once()
            ):
                repaired_current_device = True
                continue

            logger.warning(
                "[E2EE-CrossSign] 当前设备身份密钥与服务器不一致，跳过设备签名"
            )
            logger.debug(
                "[E2EE-CrossSign] 设备签名失败细节："
                f"device_id={device_id} "
                f"local_ed25519={local_ed25519} server_ed25519={server_ed25519} "
                f"local_curve25519={local_curve25519} server_curve25519={server_curve25519}"
            )
            return None
        return device_keys


__all__ = ["CrossSigningDeviceSignFetchMixin"]

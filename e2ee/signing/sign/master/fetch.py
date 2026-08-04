"""Master-key and device-key lookup for cross-signing signatures."""

from astrbot.api import logger


class CrossSigningMasterSignFetchMixin:
    """为当前账号 master key 上传当前设备签名。"""

    async def _load_current_master_signing_context(
        self, target_user_id: str
    ) -> tuple[dict, dict, tuple[str, str, str, str]] | None:
        """Return (master_key, keys, identity tuple) once the current device
        matches the server view, else None."""
        repaired_current_device = False
        while True:
            response = await self.client.query_keys({target_user_id: []})
            master_key = (response.get("master_keys") or {}).get(target_user_id)
            device_keys = (
                (response.get("device_keys") or {})
                .get(target_user_id, {})
                .get(self.device_id)
            )
            if not master_key:
                logger.debug("[E2EE-CrossSign] 未找到 master key，无法添加设备签名")
                return None

            usage = master_key.get("usage")
            keys = master_key.get("keys")
            if not isinstance(usage, list) or not isinstance(keys, dict) or not keys:
                logger.debug("[E2EE-CrossSign] master key 结构无效，无法添加设备签名")
                return None

            if not device_keys:
                if (
                    not repaired_current_device
                    and await self._repair_current_device_keys_once()
                ):
                    repaired_current_device = True
                    continue
                logger.warning(
                    "[E2EE-CrossSign] 未找到当前设备密钥，无法为 master key 添加设备签名"
                )
                return None

            (
                matches,
                local_ed25519,
                local_curve25519,
                server_ed25519,
                server_curve25519,
            ) = self._current_device_matches_server(device_keys)
            if matches:
                return (
                    master_key,
                    keys,
                    (
                        local_ed25519,
                        local_curve25519,
                        server_ed25519,
                        server_curve25519,
                    ),
                )

            if (
                not repaired_current_device
                and await self._repair_current_device_keys_once()
            ):
                repaired_current_device = True
                continue

            logger.warning(
                "[E2EE-CrossSign] 当前设备身份密钥与服务器不一致，跳过 master key 设备签名"
            )
            logger.debug(
                "[E2EE-CrossSign] master key 设备签名失败细节："
                f"device_id={self.device_id} "
                f"local_ed25519={local_ed25519} server_ed25519={server_ed25519} "
                f"local_curve25519={local_curve25519} server_curve25519={server_curve25519}"
            )
            return None

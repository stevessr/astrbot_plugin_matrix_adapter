"""Cross-signing state inspection and verification diagnostics."""

from astrbot.api import logger

from .....constants import PREFIX_ED25519


class CrossSigningVerificationStateMixin:
    """同账号设备 cross-signing 状态检查与诊断日志能力。"""

    @staticmethod
    def _extract_cross_signing_key_id(key_payload: dict | None) -> str | None:
        if not isinstance(key_payload, dict):
            return None
        keys = key_payload.get("keys")
        if not isinstance(keys, dict) or not keys:
            return None
        return next(iter(keys.keys()))

    def _classify_own_device_cross_signing_state(
        self, response: dict
    ) -> dict[str, dict[str, bool]]:
        device_keys = (response.get("device_keys") or {}).get(self.user_id) or {}
        self_signing_key_id = self._extract_cross_signing_key_id(
            (response.get("self_signing_keys") or {}).get(self.user_id)
        )
        master_key = (response.get("master_keys") or {}).get(self.user_id) or {}
        master_signatures = (master_key.get("signatures") or {}).get(
            self.user_id, {}
        ) or {}

        states: dict[str, dict[str, bool]] = {}
        for device_id, device_info in device_keys.items():
            signatures = (device_info.get("signatures") or {}).get(self.user_id, {})
            states[device_id] = {
                "owner_signed": bool(
                    self_signing_key_id and self_signing_key_id in signatures
                ),
                "master_signed": f"{PREFIX_ED25519}{device_id}" in master_signatures,
            }
        return states

    def _format_masked_device_ids(self, device_ids: list[str]) -> str:
        mask = getattr(self, "_mask_device_id", None)
        if callable(mask):
            return ", ".join(mask(device_id) for device_id in device_ids)
        return ", ".join(device_ids)

    def _log_manual_same_user_verification_required(
        self, device_ids: list[str], reason: str
    ) -> None:
        if not device_ids:
            return
        logger.info(f"{reason}：{self._format_masked_device_ids(device_ids)}")
        logger.info(
            "这些同账号设备需要在对应客户端本地完成“验证此设备 / Use another device”，"
            "或使用恢复密钥恢复；当前设备不再主动发起通用 device verification。"
        )

    async def _log_same_user_verification_gap(self, device_id: str) -> None:
        current_device_id = getattr(self, "device_id", "")
        if not device_id or device_id == current_device_id:
            return
        client = getattr(self, "client", None)
        if not client or not hasattr(client, "query_keys"):
            return
        try:
            response = await client.query_keys({self.user_id: []})
            state = self._classify_own_device_cross_signing_state(response).get(
                device_id, {}
            )
            if state.get("owner_signed") and not state.get("master_signed"):
                logger.debug(
                    "目标设备已被 owner-signed，但服务器上暂无对应 device->master 签名："
                    f"{self._format_masked_device_ids([device_id])}"
                )
        except Exception as e:
            logger.debug(f"查询同账号设备主密钥验证状态失败：{e}")

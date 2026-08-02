"""Own-device verification status checks and initiation."""

import secrets

from astrbot.api import logger

from ....constants import (
    M_KEY_VERIFICATION_REQUEST,
    M_QR_CODE_SCAN_V1_METHOD,
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    M_SAS_V1_METHOD,
)


class E2EEManagerVerificationDevicesMixin:
    """检查同账号设备状态并发起设备验证请求。"""

    async def _verify_untrusted_own_devices(self):
        """Query own devices and report same-user sessions that still need local verification."""
        if not self._verification:
            return

        try:
            response = await self.client.query_keys({self.user_id: []})

            device_keys = (response.get("device_keys") or {}).get(self.user_id) or {}
            if not device_keys:
                logger.debug("未找到其他设备")
                return

            untrusted_devices = []
            owner_signed_but_not_master_verified = []
            device_states = self._classify_own_device_cross_signing_state(response)
            for device_id in device_keys.keys():
                if device_id == self.device_id:
                    continue
                state = device_states.get(device_id, {})
                if not state.get("owner_signed"):
                    untrusted_devices.append(device_id)
                elif not state.get("master_signed"):
                    owner_signed_but_not_master_verified.append(device_id)

            if not untrusted_devices and not owner_signed_but_not_master_verified:
                logger.info("所有其他设备已验证")
                return
            if untrusted_devices:
                self._log_manual_same_user_verification_required(
                    untrusted_devices,
                    "发现尚未被 owner-signed 的同账号设备",
                )
            if owner_signed_but_not_master_verified:
                self._log_manual_same_user_verification_required(
                    owner_signed_but_not_master_verified,
                    "同账号设备已 owner-signed，但对端会话尚未完成本机主密钥验证",
                )

        except Exception as e:
            logger.warning(f"查询设备验证状态失败：{e}")

    async def _initiate_verification_for_device(
        self, target_device_id: str, methods: list[str] | None = None
    ):
        """Initiate SAS verification for device."""
        if not self._verification:
            return

        txn_id = secrets.token_hex(16)
        request_methods = methods or [
            M_SAS_V1_METHOD,
            M_QR_CODE_SCAN_V1_METHOD,
            M_QR_CODE_SHOW_V1_METHOD,
            M_RECIPROCATE_V1_METHOD,
        ]

        request_content = {
            "from_device": self.device_id,
            "methods": request_methods,
            "timestamp": int(__import__("time").time() * 1000),
            "transaction_id": txn_id,
        }

        await self.client.send_to_device(
            M_KEY_VERIFICATION_REQUEST,
            {self.user_id: {target_device_id: request_content}},
            txn_id,
        )

        if self._verification:
            self._verification.initiate_verification(
                txn_id, self.user_id, target_device_id
            )

        logger.info(
            f"已向设备 {target_device_id} 发起验证请求 (txn={(txn_id or '')[:8]}...)"
        )


__all__ = ["E2EEManagerVerificationDevicesMixin"]
